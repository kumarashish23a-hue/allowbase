// Verifies Phase C (tokenization vault) end to end:
//   A. Unit tests for supabase/functions/_shared/tokenize.ts (transpiled with
//      the project's TypeScript, run in Node). detect.ts is transpiled too
//      since tokenize.ts imports detectSensitiveSpans from it.
//   B. PGlite test: 001-027 apply, the 'tokenize' policy action drives
//      allow + tokenized=true, mask wins over tokenize, monitor mode records
//      would_tokenize, privacy_tokens has RLS enabled.
// Run: node scripts/verify-tokenize.mjs
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';

let failures = 0;
function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) failures++;
}

// ---------------------------------------------------------------- A. vault unit tests
const require = createRequire(join(process.cwd(), 'package.json'));
const ts = require('typescript');

const dir = join(tmpdir(), 'dataplane-tokenize-test');
mkdirSync(dir, { recursive: true });
function transpile(relPath, outName, fixImports) {
  let src = readFileSync(relPath, 'utf8');
  if (fixImports) src = fixImports(src);
  const { outputText, diagnostics } = ts.transpileModule(src, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
    reportDiagnostics: true,
  });
  const fatal = (diagnostics ?? []).filter((d) => d.category === ts.DiagnosticCategory.Error);
  if (fatal.length > 0) {
    console.error(`TypeScript errors in ${relPath}:`);
    for (const d of fatal) console.error(' -', ts.flattenDiagnosticMessageText(d.messageText, ' '));
    process.exit(1);
  }
  const out = join(dir, outName);
  writeFileSync(out, outputText);
  return out;
}

transpile('supabase/functions/_shared/detect.ts', 'detect.mjs');
const tokenizePath = transpile(
  'supabase/functions/_shared/tokenize.ts',
  'tokenize.mjs',
  (src) => src.replace("from './detect.ts'", "from './detect.mjs'"),
);
const TK = await import(pathToFileURL(tokenizePath).href);

// 64-hex test key (never a real secret).
const TEST_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function makeVault() {
  const tokens = new Map();
  const audits = [];
  return {
    tokens,
    audits,
    create: async (e) => {
      tokens.set(e.token_id, { ...e, revoked_at: null });
    },
    lookup: async (id) => tokens.get(id) ?? null,
    recordResolve: async () => {},
    audit: async (e) => {
      audits.push(e);
    },
  };
}
const ctxFor = (vault, org = 'org-a') => ({
  vault,
  organizationId: org,
  encryptionKeyHex: TEST_KEY,
  actorUserId: 'user-1',
  actorType: 'user',
});

// Token id format
const id1 = TK.generateTokenId();
const id2 = TK.generateTokenId();
expect(TK.TOKEN_ID_PATTERN.test(id1), 'token id matches abt_tok_<22 base64url> format');
expect(id1 !== id2, 'token ids are unique');
expect(id1.startsWith('abt_tok_') && id1.length === 8 + 22, 'token id has expected length');

// tokenize replaces sensitive spans, stores ciphertext
{
  const vault = makeVault();
  const text = 'Contact jane.doe@example.com for the report.';
  const r = await TK.tokenize(text, [{ category: 'email' }], ctxFor(vault));
  expect(r.tokens.length === 1 && r.tokens[0].category === 'email', 'email span tokenized');
  expect(/abt_tok_[A-Za-z0-9_-]{22}/.test(r.text), 'token id substituted into text');
  expect(!r.text.includes('jane.doe@example.com'), 'plaintext removed from output text');
  const stored = vault.tokens.get(r.tokens[0].tokenId);
  expect(!!stored, 'token row created in vault');
  expect(stored.value_encrypted !== 'jane.doe@example.com', 'stored value is ciphertext, not plaintext');
  expect(stored.organization_id === 'org-a', 'token scoped to organization');
  expect(vault.audits.some((a) => a.action === 'token_created'), 'token creation audited');
  const auditJson = JSON.stringify(vault.audits);
  expect(!auditJson.includes('jane.doe@example.com'), 'audit rows never contain the plaintext value');
}

// findings scope is honored: phone finding does not tokenize the email
{
  const vault = makeVault();
  const r = await TK.tokenize('Contact jane.doe@example.com.', [{ category: 'phone' }], ctxFor(vault));
  expect(r.tokens.length === 0 && r.text === 'Contact jane.doe@example.com.', 'out-of-scope categories left alone');
}

// empty input passthrough
{
  const vault = makeVault();
  const r = await TK.tokenize('', [{ category: 'email' }], ctxFor(vault));
  expect(r.tokens.length === 0 && r.text === '', 'empty text passthrough');
}

// detokenize round trip
{
  const vault = makeVault();
  const ctx = ctxFor(vault);
  const t = await TK.tokenize('Email jane.doe@example.com now.', [{ category: 'email' }], ctx);
  const d = await TK.detokenize(`Provider echoed: ${t.text}`, ctx);
  expect(d.text === 'Provider echoed: Email jane.doe@example.com now.', 'detokenize restores original');
  expect(d.resolved === 1 && d.unresolved === 0, 'one token resolved');
  expect(vault.audits.some((a) => a.action === 'token_resolved'), 'resolve audited');
  expect(!JSON.stringify(vault.audits).includes('jane.doe@example.com'), 'resolve audit has no plaintext');
}

// unknown token stays opaque
{
  const vault = makeVault();
  const d = await TK.detokenize('Hello abt_tok_AAAAAAAAAAAAAAAAAAAAAA', ctxFor(vault));
  expect(d.resolved === 0 && d.unresolved === 1, 'unknown token unresolved');
  expect(d.text.includes('abt_tok_AAAAAAAAAAAAAAAAAAAAAA'), 'unknown token left in place');
}

// cross-org isolation
{
  const vault = makeVault();
  const t = await TK.tokenize('Email jane.doe@example.com now.', [{ category: 'email' }], ctxFor(vault, 'org-a'));
  const d = await TK.detokenize(t.text, ctxFor(vault, 'org-b'));
  expect(d.resolved === 0 && d.unresolved === 1, 'org B cannot resolve org A token');
  expect(!d.text.includes('jane.doe@example.com'), 'no cross-org plaintext leak');
}

// expired token refused
{
  const vault = makeVault();
  const t = await TK.tokenize('Email jane.doe@example.com now.', [{ category: 'email' }], ctxFor(vault));
  const stored = vault.tokens.get(t.tokens[0].tokenId);
  stored.expires_at = new Date(Date.now() - 1000).toISOString();
  const d = await TK.detokenize(t.text, ctxFor(vault));
  expect(d.resolved === 0 && d.unresolved === 1, 'expired token refused');
}

// revoked token refused
{
  const vault = makeVault();
  const t = await TK.tokenize('Email jane.doe@example.com now.', [{ category: 'email' }], ctxFor(vault));
  vault.tokens.get(t.tokens[0].tokenId).revoked_at = new Date().toISOString();
  const d = await TK.detokenize(t.text, ctxFor(vault));
  expect(d.resolved === 0 && d.unresolved === 1, 'revoked token refused');
}

// wrong key cannot decrypt (AES-GCM auth fails closed)
{
  const vault = makeVault();
  const t = await TK.tokenize('Email jane.doe@example.com now.', [{ category: 'email' }], ctxFor(vault));
  const badCtx = { ...ctxFor(vault), encryptionKeyHex: 'ffffffff'.repeat(16) };
  const d = await TK.detokenize(t.text, badCtx);
  expect(d.resolved === 0 && d.unresolved === 1, 'wrong vault key fails closed');
}

// bad key format rejected early
{
  const vault = makeVault();
  let threw = false;
  try {
    await TK.tokenize('Email jane.doe@example.com.', [{ category: 'email' }], { ...ctxFor(vault), encryptionKeyHex: 'nope' });
  } catch {
    threw = true;
  }
  expect(threw, 'malformed TOKEN_ENCRYPTION_KEY rejected');
}

// ---------------------------------------------------------------- B. PGlite engine test
const db = new PGlite();

// Minimal stand-in for Supabase Auth so migrations referencing auth.users apply.
await db.exec(`
  create schema if not exists auth;
  create table if not exists auth.users (
    id uuid primary key,
    email text,
    raw_user_meta_data jsonb
  );
  create or replace function auth.uid() returns uuid
    language sql stable as $$ select null::uuid $$;
`);
await db.exec(`
  do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon; end if;
    if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated; end if;
    if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role; end if;
  end $$;
`);

const migDir = 'supabase/migrations';
const files = readdirSync(migDir).filter((f) => f.endsWith('.sql')).sort();
for (const file of files) {
  let sql = readFileSync(join(migDir, file), 'utf8');
  sql = sql.replace('create extension if not exists "pgcrypto";', '-- pgcrypto skipped (PGlite)');
  await db.exec(sql);
}
expect(files.includes('027_tokenization_vault.sql'), 'migration 027 present and applied');

const ORG = 'c0000000-0000-4000-8000-000000000001';
const USER = 'c0000000-0000-4000-8000-0000000000a1';
const MODEL = 'c0000000-0000-4000-8000-0000000000b1';
await db.exec(`
  create or replace function auth.uid() returns uuid
    language sql stable as $$ select '${USER}'::uuid $$;
  insert into public.organizations (id, name, slug) values ('${ORG}', 'Tok Co', 'tok-co');
  insert into auth.users (id, email) values ('${USER}', 'tok@example.com');
  insert into public.organization_members (organization_id, user_id, role, status)
  values ('${ORG}', '${USER}', 'admin', 'active');
  insert into public.ai_models (id, organization_id, name, provider, model_identifier)
  values ('${MODEL}', '${ORG}', 'gpt-test', 'openai', 'gpt-test');
  update public.organizations set enforcement_mode = 'enforce' where id = '${ORG}';
`);

// tokenize policy: content.category email -> tokenize
await db.exec(`
  insert into public.policies (organization_id, name, description, status, priority, rule, action)
  values ('${ORG}', 'Tokenize PII test', 'test', 'active', 5,
    '{"conditions":[{"field":"content.category","operator":"in","value":["email","phone"]}]}'::jsonb,
    'tokenize')
`);
const findings = '[{"detector":"regex-v1","category":"email","severity":"medium","confidence":0.95,"count":1}]';
const tokRes = await db.query(
  `select public.evaluate_ai_request('${ORG}','${MODEL}','Support reply',array[]::uuid[],null,null,'chat','${findings}'::jsonb) as r`,
);
const tk = tokRes.rows[0].r;
expect(tk.decision === 'allow' && tk.tokenized === true, 'tokenize policy allows with tokenized=true');
expect(tk.masked !== true, 'tokenize does not set masked');

const tokMeta = await db.query(`select metadata from public.ai_requests where id = '${tk.request_id}'::uuid`);
expect(tokMeta.rows[0].metadata.tokenized === true, 'request metadata records tokenized');
const tokRisk = await db.query(`select title from public.risk_events where ai_request_id = '${tk.request_id}'::uuid`);
expect(tokRisk.rows.length === 1 && /tokenized/.test(tokRisk.rows[0].title), 'risk event raised for tokenization');

// mask wins when both trigger (deterministic priority)
await db.exec(`
  insert into public.policies (organization_id, name, description, status, priority, rule, action)
  values ('${ORG}', 'Mask PII higher', 'test', 'active', 4,
    '{"conditions":[{"field":"content.category","operator":"in","value":["email"]}]}'::jsonb,
    'mask')
`);
const bothRes = await db.query(
  `select public.evaluate_ai_request('${ORG}','${MODEL}','Support reply',array[]::uuid[],null,null,'chat','${findings}'::jsonb) as r`,
);
const both = bothRes.rows[0].r;
expect(both.masked === true && both.tokenized !== true, 'mask outranks tokenize when both trigger');

// monitor mode: would_tokenize recorded, nothing transformed
await db.exec(`update public.organizations set enforcement_mode = 'monitor' where id = '${ORG}'`);
await db.exec(`delete from public.policies where name = 'Mask PII higher' and organization_id = '${ORG}'`);
const monRes = await db.query(
  `select public.evaluate_ai_request('${ORG}','${MODEL}','Support reply',array[]::uuid[],null,null,'chat','${findings}'::jsonb) as r`,
);
const mon = monRes.rows[0].r;
expect(mon.decision === 'allow' && mon.tokenized === false && mon.would_tokenize === true,
  'monitor mode records would_tokenize without tokenizing');

// privacy_tokens table: exists, RLS enabled, select policy present
const tbl = await db.query(
  `select relname from pg_class where relname = 'privacy_tokens'`,
);
expect(tbl.rows.length === 1, 'privacy_tokens table exists');
const rls = await db.query(
  `select relrowsecurity from pg_class where relname = 'privacy_tokens'`,
);
expect(rls.rows[0].relrowsecurity === true, 'privacy_tokens has RLS enabled');
const pol = await db.query(
  `select policyname from pg_policies where tablename = 'privacy_tokens'`,
);
expect(pol.rows.some((r) => r.policyname === 'privacy_tokens_select'), 'member select policy exists');

// action vocabulary accepts tokenize
const vocab = await db.query(
  `select conname from pg_constraint where conname = 'policies_action_check'`,
);
expect(vocab.rows.length === 1, 'policies_action_check constraint present');

if (failures > 0) {
  console.error(`\n${failures} tokenize check(s) FAILED`);
  process.exit(1);
}
console.log('\nAll tokenize checks passed.');
