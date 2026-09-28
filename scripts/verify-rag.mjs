// Verifies Phase E (RAG security):
//   Part 1 — unit tests for supabase/functions/_shared/rag.ts (transpiled
//   with the project's TypeScript, run in Node): chunking invariants,
//   cosine similarity, ranking, clearance mirrors, embedding-call batching
//   (mock fetch).
//   Part 2 — migration 028 against in-memory Postgres (PGlite): the ACL
//   model end to end — clearance ceilings, grants, tenant isolation,
//   clearance-capping on direct RPC calls, and RLS on the tables.
// Run: node scripts/verify-rag.mjs
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { PGlite } from '@electric-sql/pglite';

let failures = 0;
function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) failures++;
}

// --- Part 1: pure module -------------------------------------------------------
const require = createRequire(join(process.cwd(), 'package.json'));
const ts = require('typescript');
const dir = join(tmpdir(), 'dataplane-rag-test');
mkdirSync(dir, { recursive: true });

const src = readFileSync('supabase/functions/_shared/rag.ts', 'utf8');
const { outputText, diagnostics } = ts.transpileModule(src, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
  reportDiagnostics: true,
});
const fatal = (diagnostics ?? []).filter((d) => d.category === ts.DiagnosticCategory.Error);
if (fatal.length > 0) {
  for (const d of fatal) console.error(' -', ts.flattenDiagnosticMessageText(d.messageText, ' '));
  process.exit(1);
}
const ragPath = join(dir, 'rag.mjs');
writeFileSync(ragPath, outputText);
const R = await import(pathToFileURL(ragPath).href);

expect(R.RAG_VERSION === 'rag-v1', 'rag version stamped');

// Chunking: invariants.
{
  expect(R.chunkText('').length === 0, 'empty text -> no chunks');
  expect(R.chunkText('   \n\n  ').length === 0, 'whitespace only -> no chunks');
  const one = R.chunkText('Short text.');
  expect(one.length === 1 && one[0] === 'Short text.', 'short text -> single chunk');
}
{
  // Long text: every chunk <= maxChars, overlap carries context forward.
  const text = Array.from({ length: 40 }, (_, i) => `Sentence number ${i} carries some content here.`).join(' ');
  const chunks = R.chunkText(text, { maxChars: 200, overlapChars: 50 });
  expect(chunks.length > 3, 'long text splits into several chunks');
  expect(chunks.every((c) => c.length <= 200), 'no chunk exceeds maxChars');
  expect(chunks.every((c) => c.length > 0), 'no empty chunks');
  // Overlap: a sentence straddling a boundary appears in both neighbors.
  const joined = chunks.join(' ');
  expect(text.split(' ').every((w) => joined.includes(w)), 'no words lost across chunks');
}
{
  // A single very long run is hard-split, not dropped.
  const run = 'x'.repeat(500);
  const chunks = R.chunkText(run, { maxChars: 100, overlapChars: 10 });
  expect(chunks.length === 5 && chunks.every((c) => c.length <= 100), 'long run hard-splits cleanly');
  expect(chunks.join('') === run, 'hard-split is lossless');
}
{
  // Paragraphs stay together when they fit.
  const chunks = R.chunkText('Para one here.\n\nPara two here.', { maxChars: 1000 });
  expect(chunks.length === 1 && chunks[0].includes('Para one') && chunks[0].includes('Para two'), 'fitting paragraphs pack together');
}

// Cosine similarity.
{
  expect(Math.abs(R.cosineSimilarity([1, 0, 0], [1, 0, 0]) - 1) < 1e-9, 'identical vectors -> 1');
  expect(Math.abs(R.cosineSimilarity([1, 0], [0, 1])) < 1e-9, 'orthogonal vectors -> 0');
  expect(Math.abs(R.cosineSimilarity([1, 2], [-1, -2]) + 1) < 1e-9, 'opposite vectors -> -1');
  expect(R.cosineSimilarity([1, 2], [1, 2, 3]) === 0, 'dimension mismatch -> 0, never NaN');
  expect(R.cosineSimilarity([], []) === 0, 'empty vectors -> 0');
  expect(R.cosineSimilarity([0, 0], [1, 1]) === 0, 'zero vector -> 0');
  expect(R.cosineSimilarity([NaN, 1], [1, 1]) === 0, 'NaN input -> 0');
}

// Ranking: orders by similarity, honors topK, excludes unusable embeddings.
{
  const cands = [
    { id: 'a', embedding: [1, 0] },
    { id: 'b', embedding: [0, 1] },
    { id: 'c', embedding: [0.9, 0.1] },
    { id: 'noemb', embedding: null },
    { id: 'wrongdim', embedding: [1, 0, 0] },
  ];
  const ranked = R.rankBySimilarity([1, 0], cands, 10);
  expect(ranked.map((r) => r.candidate.id).join(',') === 'a,c,b', 'ranked by descending similarity');
  expect(R.rankBySimilarity([1, 0], cands, 2).length === 2, 'topK honored');
  expect(!ranked.some((r) => r.candidate.id === 'noemb' || r.candidate.id === 'wrongdim'), 'unusable embeddings excluded, never guessed');
  expect(ranked[0].score > ranked[1].score, 'scores attached and ordered');
}

// Clearance mirrors of the SQL maps.
{
  expect(R.clearanceRank('public') === 0 && R.clearanceRank('restricted') === 3, 'clearance ranks ordered');
  expect(R.clearanceRank('bogus') === -1, 'unknown clearance -> -1');
  expect(R.roleMaxClearance('owner') === 'restricted', 'owner -> restricted');
  expect(R.roleMaxClearance('developer') === 'confidential', 'developer -> confidential');
  expect(R.roleMaxClearance('analyst') === 'internal', 'analyst -> internal');
  expect(R.roleMaxClearance('viewer') === 'public', 'viewer -> public');
  expect(R.roleMaxClearance('nobody') === 'public', 'unknown role -> public (fail closed)');
}

// embedTexts: batching, order, auth header, error mapping (mock fetch).
{
  const calls = [];
  const mockFetch = async (url, opts) => {
    calls.push({ url, opts });
    const body = JSON.parse(opts.body);
    return {
      ok: true,
      json: async () => ({
        // Return reversed to prove the client re-sorts by index.
        data: body.input.map((_, i) => ({ embedding: [i, i + 1], index: i })).reverse(),
      }),
    };
  };
  const texts = Array.from({ length: 70 }, (_, i) => `text ${i}`);
  const embs = await R.embedTexts({ baseUrl: 'https://api.openai.com/v1/', apiKey: 'k', model: 'm' }, texts, mockFetch);
  expect(calls.length === 2, '70 texts batched into 2 embedding calls');
  expect(calls[0].url === 'https://api.openai.com/v1/embeddings', 'trailing slash trimmed on base URL');
  expect(calls[0].opts.headers.Authorization === 'Bearer k', 'provider key sent as bearer');
  expect(JSON.parse(calls[0].opts.body).model === 'm', 'configured model passed through');
  expect(embs.length === 70 && embs[0][0] === 0 && embs[63][0] === 63, 'embeddings returned in input order (batch 1)');
  expect(embs[64][0] === 0 && embs[69][0] === 5, 'embeddings returned in input order (batch 2)');
  let threw = false;
  try {
    await R.embedTexts({ baseUrl: 'https://x', apiKey: 'k', model: '' }, ['a'], mockFetch);
  } catch {
    threw = true;
  }
  expect(threw, 'missing embedding_model throws (no silent default)');
  const badFetch = async () => ({ ok: false, status: 401 });
  threw = false;
  try {
    await R.embedTexts({ baseUrl: 'https://x', apiKey: 'k', model: 'm' }, ['a'], badFetch);
  } catch (e) {
    threw = /returned 401/.test(e.message) && !/Bearer/.test(e.message);
  }
  expect(threw, 'provider errors surface status only, never key material');
}

// --- Part 2: migration 028 in PGlite ------------------------------------------
const migDir = new URL('../supabase/migrations/', import.meta.url).pathname;
const files = readdirSync(migDir).filter((f) => f.endsWith('.sql')).sort();
const db = new PGlite();
await db.exec(`
  create schema if not exists auth;
  create table if not exists auth.users (id uuid primary key, email text, raw_user_meta_data jsonb);
  create or replace function auth.uid() returns uuid language sql stable as $$ select null::uuid $$;
`);
await db.exec(`
  do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon; end if;
    if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated; end if;
    if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role; end if;
  end $$;
`);
const FALLBACK_UUID = `
  create or replace function public.gen_random_uuid() returns uuid
  language sql as $$ select md5(random()::text || clock_timestamp()::text)::uuid $$;
`;
for (const file of files) {
  let sql = readFileSync(join(migDir, file), 'utf8');
  sql = sql.replace('create extension if not exists "pgcrypto";', '-- pgcrypto stubbed in verification');
  await db.exec(FALLBACK_UUID + sql);
}
console.log('ok   all migrations incl. 028 apply');

// Supabase grants anon/authenticated default table access; PGlite needs it explicit.
await db.exec(`
  grant select, insert, update, delete on public.rag_documents to authenticated;
  grant select, insert, update, delete on public.rag_chunks to authenticated;
  grant select, insert, update, delete on public.rag_grants to authenticated;
`);

const ORG = 'c0000000-0000-4000-8000-000000000001';
const ORG2 = 'c0000000-0000-4000-8000-000000000002';
const OWNER = 'c0000000-0000-4000-8000-0000000000a1';
const DEV = 'c0000000-0000-4000-8000-0000000000a2';
const VIEWER = 'c0000000-0000-4000-8000-0000000000a3';
const OUTSIDER = 'c0000000-0000-4000-8000-0000000000a4';
const ANALYST = 'c0000000-0000-4000-8000-0000000000a5';

await db.exec(`
  insert into auth.users (id, email) values
    ('${OWNER}', 'owner@x.test'), ('${DEV}', 'dev@x.test'),
    ('${VIEWER}', 'viewer@x.test'), ('${OUTSIDER}', 'outsider@x.test'),
    ('${ANALYST}', 'analyst@x.test');
  insert into public.organizations (id, name, slug) values
    ('${ORG}', 'RAG Org', 'rag-org'),
    ('${ORG2}', 'Other Org', 'other-org');
  insert into public.organization_members (organization_id, user_id, role, status) values
    ('${ORG}', '${OWNER}', 'owner', 'active'),
    ('${ORG}', '${DEV}', 'developer', 'active'),
    ('${ORG}', '${VIEWER}', 'viewer', 'active'),
    ('${ORG}', '${ANALYST}', 'analyst', 'active'),
    ('${ORG2}', '${OUTSIDER}', 'owner', 'active');
`);
const setUser = async (id) => {
  await db.exec(`create or replace function auth.uid() returns uuid language sql stable as $$ select '${id}'::uuid $$;`);
};

await setUser(OWNER);
const docs = await db.query(`
  insert into public.rag_documents (organization_id, title, classification, created_by) values
    ('${ORG}', 'Public handbook', 'public', '${OWNER}'),
    ('${ORG}', 'Internal runbook', 'internal', '${OWNER}'),
    ('${ORG}', 'Confidential roadmap', 'confidential', '${OWNER}'),
    ('${ORG}', 'Restricted salaries', 'restricted', '${OWNER}')
  returning id, title;
`);
const otherDoc = (
  await db.query(`
    insert into public.rag_documents (organization_id, title, classification, created_by) values
      ('${ORG2}', 'Other org secret', 'restricted', '${OUTSIDER}')
    returning id;
  `)
).rows[0].id;
const docId = Object.fromEntries(docs.rows.map((r) => [r.title, r.id]));
// Chunks with tiny 3-dim embeddings for the similarity test.
for (const [title, id] of Object.entries(docId)) {
  await db.query(
    `insert into public.rag_chunks (organization_id, document_id, chunk_index, content, embedding, embedding_model)
     values ('${ORG}', '${id}', 0, 'chunk of ${title}', '{0.1,0.2,0.3}', 'test-model')`,
  );
}
await db.query(
  `insert into public.rag_chunks (organization_id, document_id, chunk_index, content, embedding, embedding_model)
   values ('${ORG2}', '${otherDoc}', 0, 'chunk of other org secret', '{0.9,0.9,0.9}', 'test-model')`,
);
// Grants: developer may read the confidential roadmap; analyst may read the
// internal runbook; viewer holds a grant on the internal runbook too — but
// their clearance ceiling (public) still blocks it, proving grants cannot
// escalate above clearance.
await db.exec(`
  insert into public.rag_grants (organization_id, document_id, grantee_user_id, created_by) values
    ('${ORG}', '${docId['Confidential roadmap']}', '${DEV}', '${OWNER}'),
    ('${ORG}', '${docId['Internal runbook']}', '${ANALYST}', '${OWNER}'),
    ('${ORG}', '${docId['Internal runbook']}', '${VIEWER}', '${OWNER}');
`);

async function candidatesAs(userId, clearance, limit = 500) {
  await setUser(userId);
  const r = await db.query(`select * from public.rag_search_candidates('${ORG}'::uuid, '${clearance}', ${limit})`);
  return r.rows;
}

// Clearance ceiling: viewer (public) sees only public docs — even their
// grant on the internal runbook cannot lift them above their clearance.
{
  const rows = await candidatesAs(VIEWER, 'public');
  const titles = rows.map((r) => r.title);
  expect(titles.length === 1 && titles[0] === 'Public handbook', 'viewer sees only the public document (grant cannot exceed clearance)');
}
// Analyst (internal) with a grant reads the internal runbook.
{
  const rows = await candidatesAs(ANALYST, 'internal');
  const titles = rows.map((r) => r.title).sort();
  expect(
    titles.length === 2 && titles.includes('Public handbook') && titles.includes('Internal runbook'),
    'analyst sees public + granted internal',
  );
}
// Developer (confidential) sees public + granted internal? No — developer has
// no grant on internal; sees public + granted confidential.
{
  const rows = await candidatesAs(DEV, 'confidential');
  const titles = rows.map((r) => r.title).sort();
  expect(
    titles.length === 2 && titles.includes('Public handbook') && titles.includes('Confidential roadmap'),
    'developer sees public + granted confidential, not ungranted internal/restricted',
  );
}
// Owner (restricted) with NO grant on the restricted doc cannot see it:
// clearance is a ceiling, not a pass.
{
  const rows = await candidatesAs(OWNER, 'restricted');
  const titles = rows.map((r) => r.title);
  expect(!titles.includes('Restricted salaries'), 'owner without a grant cannot see the restricted doc');
  expect(titles.includes('Public handbook'), 'owner still sees public docs');
}
// Grant the owner on the restricted doc -> visible.
{
  await setUser(OWNER);
  await db.exec(`insert into public.rag_grants (organization_id, document_id, grantee_user_id) values ('${ORG}', '${docId['Restricted salaries']}', '${OWNER}')`);
  const rows = await candidatesAs(OWNER, 'restricted');
  expect(rows.map((r) => r.title).includes('Restricted salaries'), 'explicit grant unlocks the restricted doc for the owner');
}
// Anti-escalation: a direct RPC call with clearance=restricted is capped at
// the caller's role-derived maximum.
{
  const rows = await candidatesAs(VIEWER, 'restricted');
  expect(rows.length === 1 && rows[0].title === 'Public handbook', 'requested clearance capped at role maximum (viewer)');
  const devRows = await candidatesAs(DEV, 'restricted');
  expect(!devRows.map((r) => r.title).includes('Restricted salaries'), 'developer cannot escalate to restricted via the RPC');
}
// Tenant isolation: the other org's document never appears.
{
  const rows = await candidatesAs(OWNER, 'restricted');
  expect(!rows.map((r) => r.title).includes('Other org secret'), 'cross-org documents never leak into candidates');
}
// Outsider (not a member) gets an exception, not an empty list.
{
  await setUser(OUTSIDER);
  let threw = false;
  try {
    await db.query(`select * from public.rag_search_candidates('${ORG}'::uuid, 'restricted', 500)`);
  } catch (e) {
    threw = /not a member/.test(e.message);
  }
  expect(threw, 'non-member RPC call raises instead of returning rows');
}
// Invalid clearance raises.
{
  await setUser(OWNER);
  let threw = false;
  try {
    await db.query(`select * from public.rag_search_candidates('${ORG}'::uuid, 'bogus', 500)`);
  } catch (e) {
    threw = /invalid clearance/.test(e.message);
  }
  expect(threw, 'invalid clearance raises');
}
// rag_can_read_document agrees with the RPC (single source of truth).
{
  await setUser(ANALYST);
  const r = await db.query(`select public.rag_can_read_document('${docId['Internal runbook']}'::uuid) as v`);
  expect(r.rows[0].v === true, 'analyst can read granted internal doc via helper');
  await setUser(VIEWER);
  const r2 = await db.query(`select public.rag_can_read_document('${docId['Internal runbook']}'::uuid) as v`);
  expect(r2.rows[0].v === false, 'viewer grant above clearance still blocked via helper');
  const r3 = await db.query(`select public.rag_can_read_document('${docId['Confidential roadmap']}'::uuid) as v`);
  expect(r3.rows[0].v === false, 'viewer cannot read confidential doc via helper');
}
// RLS: as the authenticated role, direct table reads obey the same filter.
{
  await setUser(VIEWER);
  await db.exec('set role authenticated');
  const docs2 = await db.query('select title from public.rag_documents order by title');
  const titles = docs2.rows.map((r) => r.title);
  expect(titles.length === 1 && titles[0] === 'Public handbook', 'RLS: viewer reads only the public doc');
  await db.exec('reset role');
  await setUser(ANALYST);
  await db.exec('set role authenticated');
  const docs3 = await db.query('select title from public.rag_documents order by title');
  const titles3 = docs3.rows.map((r) => r.title).sort();
  expect(
    titles3.length === 2 && titles3.includes('Public handbook') && titles3.includes('Internal runbook'),
    'RLS: analyst reads public + granted internal docs',
  );
  expect(!titles3.includes('Confidential roadmap') && !titles3.includes('Restricted salaries'), 'RLS: analyst blocked from ungranted docs');
  const chunks = await db.query('select content from public.rag_chunks');
  expect(!chunks.rows.some((r) => r.content.includes('roadmap')), 'RLS: chunks of hidden docs are hidden too');
  await db.exec('reset role');
}
// Grants are privileged: viewer cannot insert a grant for themselves (RLS).
{
  await setUser(VIEWER);
  await db.exec('set role authenticated');
  let threw = false;
  try {
    await db.exec(`insert into public.rag_grants (organization_id, document_id, grantee_user_id) values ('${ORG}', '${docId['Restricted salaries']}', '${VIEWER}')`);
  } catch {
    threw = true;
  }
  await db.exec('reset role');
  expect(threw, 'RLS: viewer cannot self-grant');
}
// Similarity happens over filtered rows only: rank the developer's
// candidates in JS and confirm the restricted chunk is unrankable.
{
  const rows = await candidatesAs(DEV, 'confidential');
  const ranked = R.rankBySimilarity([0.1, 0.2, 0.3], rows, 5);
  expect(ranked.length === 2, 'ranking only ever sees the 2 authorized candidates');
  expect(!ranked.some((r) => r.candidate.title === 'Restricted salaries'), 'restricted chunk cannot win on similarity alone');
}

if (failures > 0) {
  console.error(`\n${failures} RAG check(s) FAILED`);
  process.exit(1);
}
console.log('\nAll RAG checks passed.');
