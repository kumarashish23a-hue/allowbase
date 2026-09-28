// Verifies migration 026 (Phase B quick wins) end to end:
//   A. Unit tests for supabase/functions/_shared/ssrf.ts (transpiled with the
//      project's TypeScript, run in Node): sync guards plus the async
//      resolve-then-check with an injected fake Deno.resolveDns.
//   B. PGlite test: 001-026 apply, approval expiry (expire_stale_approvals,
//      decide_approval refuses expired, linked request fails closed), and the
//      ai_models unique constraint.
// Run: node scripts/verify-phaseb.mjs
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

// ---------------------------------------------------------------- A. ssrf.ts
const require = createRequire(join(process.cwd(), 'package.json'));
const ts = require('typescript');
const src = readFileSync('supabase/functions/_shared/ssrf.ts', 'utf8');
const { outputText, diagnostics } = ts.transpileModule(src, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
  reportDiagnostics: true,
});
const fatal = (diagnostics ?? []).filter((d) => d.category === ts.DiagnosticCategory.Error);
if (fatal.length > 0) {
  console.error('TypeScript errors in ssrf.ts:');
  for (const d of fatal) console.error(' -', ts.flattenDiagnosticMessageText(d.messageText, ' '));
  process.exit(1);
}
const dir = join(tmpdir(), 'dataplane-ssrf-test');
mkdirSync(dir, { recursive: true });
const compiled = join(dir, 'ssrf.mjs');
writeFileSync(compiled, outputText);
const S = await import(pathToFileURL(compiled).href);

// Sync guards still hold.
expect(S.isSafeProviderUrl('https://api.example.com/v1') === true, 'public https URL passes');
expect(S.isSafeProviderUrl('http://api.example.com/v1') === false, 'http rejected');
expect(S.isSafeProviderUrl('https://169.254.169.254/') === false, 'link-local IP literal rejected');
expect(S.isSafeProviderUrl('https://10.0.0.5/') === false, 'private IP literal rejected');
expect(S.isSafeProviderUrl('https://user:pass@api.example.com/') === false, 'credentials in URL rejected');

// Async resolve-then-check with a fake DNS layer (no network in tests).
const realDeno = globalThis.Deno;
globalThis.Deno = {
  resolveDns: async (host, _type) => {
    if (host === 'evil.example.com') return ['10.0.0.5'];
    if (host === 'rebind.example.com') return ['93.184.216.34', '192.168.1.9'];
    if (host === 'good.example.com') return ['93.184.216.34'];
    if (host === 'v6evil.example.com') return ['::1'];
    return [];
  },
};

expect(await S.isSafeProviderUrlAsync('https://good.example.com/v1') === true, 'hostname resolving to public IP passes');
expect(await S.isSafeProviderUrlAsync('https://evil.example.com/v1') === false, 'hostname resolving to private IP rejected');
expect(await S.isSafeProviderUrlAsync('https://rebind.example.com/v1') === false, 'mixed public+private resolution rejected');
expect(await S.isSafeProviderUrlAsync('https://v6evil.example.com/v1') === false, 'hostname resolving to IPv6 loopback rejected');
expect(await S.isSafeProviderUrlAsync('https://nx.example.com/v1') === false, 'unresolvable hostname refused');
expect(await S.isSafeProviderUrlAsync('https://169.254.169.254/') === false, 'async: IP literal still rejected by sync pass');
expect(await S.isSafeProviderUrlAsync('https://93.184.216.34/v1') === true, 'async: public IP literal needs no DNS');
expect(await S.isSafeProviderUrlAsync('http://good.example.com/') === false, 'async: http rejected before DNS');

// No Deno in the runtime -> sync verdict stands (documented fallback).
delete globalThis.Deno;
expect(await S.isSafeProviderUrlAsync('https://good.example.com/v1') === true, 'no DNS runtime: sync verdict stands for public host');
expect(await S.isSafeProviderUrlAsync('https://10.0.0.5/') === false, 'no DNS runtime: literal still rejected');
globalThis.Deno = realDeno;

// ---------------------------------------------------------------- B. SQL path
const migDir = new URL('../supabase/migrations/', import.meta.url).pathname;
const files = readdirSync(migDir).filter((f2) => f2.endsWith('.sql')).sort();

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
await db.exec(`
  create or replace function public.gen_random_uuid() returns uuid
  language sql as $$ select md5(random()::text || clock_timestamp()::text)::uuid $$;
  create or replace function public.gen_random_bytes(n int) returns bytea
  language sql as $$
    select decode(substring(md5(random()::text || clock_timestamp()::text)
      || md5(clock_timestamp()::text || random()::text), 1, 2 * n), 'hex')
  $$;
  create or replace function public.digest(data text, algo text) returns bytea
  language sql as $$ select decode(md5(data || '|a|' || algo) || md5(data || '|b|' || algo), 'hex') $$;
`);
for (const file of files) {
  let sql = readFileSync(join(migDir, file), 'utf8');
  sql = sql.replace('create extension if not exists "pgcrypto";', '-- stubbed');
  try {
    await db.exec(sql);
  } catch (error) {
    console.error(`FAIL migration ${file}: ${error.message}`);
    process.exit(1);
  }
}
console.log(`ok    all migrations (${files[0].slice(0, 3)}-${files[files.length - 1].slice(0, 3)}) apply`);

const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaa001';
const ADMIN = 'b1111111-1111-4111-8111-111111111111';
const MODEL = 'f2222222-2222-4222-8222-222222222222';
const REQ1 = 'c3333333-3333-4333-8333-333333333333';
const REQ2 = 'c4444444-4444-4444-8444-444444444444';
const APR1 = 'd5555555-5555-4555-8555-555555555555';
const APR2 = 'd6666666-6666-4666-8666-666666666666';

await db.exec(`
  insert into auth.users (id, email) values ('${ADMIN}', 'admin@test.local');
  create or replace function auth.uid() returns uuid language sql stable as $$ select '${ADMIN}'::uuid $$;
  insert into public.organizations (id, name, slug, enforcement_mode) values ('${ORG}', 'Test Org', 'test-org', 'enforce');
  insert into public.organization_members (organization_id, user_id, role, status)
  values ('${ORG}', '${ADMIN}', 'admin', 'active');
  insert into public.ai_models (id, organization_id, name, provider, model_identifier, is_external, is_approved)
  values ('${MODEL}', '${ORG}', 'support-copilot', 'test', 'support-copilot', true, true);
`);

// B1: a stale pending approval + its linked request.
await db.exec(`
  insert into public.ai_requests (id, organization_id, ai_model_id, purpose, status)
  values ('${REQ1}', '${ORG}', '${MODEL}', 'stale request', 'pending_approval');
  insert into public.approval_requests (id, organization_id, ai_request_id, status, requested_by, expires_at)
  values ('${APR1}', '${ORG}', '${REQ1}', 'pending', '${ADMIN}', now() - interval '1 hour');
`);

let r = await db.query(`select public.expire_stale_approvals() as n`);
expect(r.rows[0].n === 1, 'expire_stale_approvals sweeps one overdue approval');

r = await db.query(`select status from public.approval_requests where id = '${APR1}'`);
expect(r.rows[0].status === 'expired', 'overdue approval marked expired');

r = await db.query(`select status from public.ai_requests where id = '${REQ1}'`);
expect(r.rows[0].status === 'blocked', 'linked request fails closed to blocked');

r = await db.query(
  `select count(*)::int as n from public.audit_logs where action = 'approval_expired' and resource_id = '${APR1}'`,
);
expect(r.rows[0].n === 1, 'expiry writes a system audit row');

let threw = '';
try {
  await db.query(`select public.decide_approval('${APR1}', 'approved')`);
} catch (e) {
  threw = e.message;
}
expect(threw.includes('expired'), 'decide_approval refuses an expired approval');

r = await db.query(`select status from public.approval_requests where id = '${APR1}'`);
expect(r.rows[0].status === 'expired', 'refused decision leaves the approval expired');

// B1: a fresh approval still works end to end.
await db.exec(`
  insert into public.ai_requests (id, organization_id, ai_model_id, purpose, status)
  values ('${REQ2}', '${ORG}', '${MODEL}', 'fresh request', 'pending_approval');
  insert into public.approval_requests (id, organization_id, ai_request_id, status, requested_by, expires_at)
  values ('${APR2}', '${ORG}', '${REQ2}', 'pending', '${ADMIN}', now() + interval '23 hours');
`);
r = await db.query(`select public.decide_approval('${APR2}', 'approved', 'looks fine') as v`);
expect(r.rows[0].v.decision === 'approved', 'fresh approval can be approved');
r = await db.query(`select status from public.ai_requests where id = '${REQ2}'`);
expect(r.rows[0].status === 'allowed', 'approved request becomes allowed');

// B3: the unique constraint exists and bites.
r = await db.query(
  `select count(*)::int as n from pg_constraint where conname = 'uq_ai_models_org_provider_name'`,
);
expect(r.rows[0].n === 1, 'uq_ai_models_org_provider_name exists');

let dupCode = '';
try {
  await db.exec(`
    insert into public.ai_models (organization_id, name, provider, model_identifier)
    values ('${ORG}', 'support-copilot', 'test', 'support-copilot');
  `);
} catch (e) {
  dupCode = e.code || '';
}
expect(dupCode === '23505', 'duplicate (org, provider, name) rejected with 23505');

await db.exec(`
  insert into public.ai_models (organization_id, name, provider, model_identifier)
  values ('${ORG}', 'other-model', 'test', 'other-model');
`);
r = await db.query(
  `select count(*)::int as n from public.ai_models where organization_id = '${ORG}' and provider = 'test'`,
);
expect(r.rows[0].n === 2, 'distinct model names still register');

console.log(failures === 0 ? '\nAll Phase B checks passed.' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
