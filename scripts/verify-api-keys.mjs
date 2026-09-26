// Verifies migration 011 (API keys + ingest_api_event) against PGlite.
// Run: node scripts/verify-api-keys.mjs
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PGlite } from '@electric-sql/pglite';

const dir = new URL('../supabase/migrations/', import.meta.url).pathname;
const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();

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
// PGlite has no pgcrypto: deterministic stand-ins (verification only).
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

let failed = false;
for (const file of files) {
  let sql = readFileSync(join(dir, file), 'utf8');
  sql = sql.replace('create extension if not exists "pgcrypto";', '-- stubbed');
  try {
    await db.exec(sql);
  } catch (error) {
    failed = true;
    console.error(`FAIL ${file}: ${error.message}`);
  }
}
if (failed) process.exit(1);
console.log('ok    all migrations apply');

const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ADMIN = 'b0000000-0000-4000-8000-0000000000a2';
const VIEWER = 'b0000000-0000-4000-8000-0000000000b3';
const CLAUDE = 'f0000000-0000-4000-8000-000000000002';
const CUSTOMERS = 'd0000000-0000-4000-8000-000000000001';
const AGENT1 = '10000000-0000-4000-8000-000000000001';
const AGENT2 = '10000000-0000-4000-8000-000000000002';

function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) process.exitCode = 1;
}

async function asUser(userId, role) {
  await db.exec(`
    insert into auth.users (id, email) values ('${userId}', '${userId}@test.local')
    on conflict (id) do nothing;
    create or replace function auth.uid() returns uuid
    language sql stable as $$ select '${userId}'::uuid $$;
    insert into public.organization_members (organization_id, user_id, role, status)
    values ('${ORG}', '${userId}', '${role}', 'active')
    on conflict (organization_id, user_id) do update set status = 'active', role = '${role}';
  `);
}

// 1. Admin mints a key: plaintext returned once, only the hash stored.
await asUser(ADMIN, 'admin');
const created = await db.query(
  `select public.create_api_key('${ORG}', 'Test backend', array['ingest'], null) as k`,
);
const k = created.rows[0].k;
expect(
  typeof k.key === 'string' && k.key.startsWith('dcp_live_') && k.key.length === 73,
  'create_api_key returns a dcp_live_ key once',
);
expect(k.prefix === k.key.slice(0, 12), 'prefix matches the key');
const stored = await db.query(`select key_hash, key_prefix from public.api_keys where id = '${k.id}'`);
expect(
  stored.rows[0].key_hash !== k.key && stored.rows[0].key_hash.length === 64,
  'only the hash is stored, never the plaintext',
);
const KEY_HASH = stored.rows[0].key_hash;

// 2. Plain members cannot mint keys.
await asUser(VIEWER, 'viewer');
let memberMintFailed = false;
try {
  await db.query(`select public.create_api_key('${ORG}', 'sneaky', array['ingest'], null)`);
} catch (error) {
  memberMintFailed = error.code === '42501';
}
expect(memberMintFailed, 'viewer cannot mint a key (42501)');
await asUser(ADMIN, 'admin');

// 3. Ingest with a valid key: runs the real policy engine.
const before = await db.query(`select count(*)::int as n from public.ai_requests`);
const ingested = await db.query(
  `select public.ingest_api_event('${KEY_HASH}', 'evt_test_1', '${CLAUDE}', null,
     'Customer Analysis', array['${CUSTOMERS}'::uuid], null, 'data_access') as r`,
);
const r = ingested.rows[0].r;
expect(r.decision === 'block', 'ingest evaluates policies (block on PII -> external)');
expect(r.event_id === 'evt_test_1' && r.idempotent_replay === false, 'event metadata returned');
const storedReq = await db.query(
  `select event_id, status, metadata->>'api_key_prefix' as prefix from public.ai_requests where id = '${r.request_id}'`,
);
expect(storedReq.rows[0].event_id === 'evt_test_1', 'event_id persisted on the request');
expect(storedReq.rows[0].prefix === k.prefix, 'key prefix linked on the request');
const auditRow = await db.query(
  `select actor_type, action from public.audit_logs where resource_id = '${r.request_id}' and action = 'api_event_ingested'`,
);
expect(
  auditRow.rows.length === 1 && auditRow.rows[0].actor_type === 'system',
  'ingestion is audit-logged as a system key call',
);

// 4. Idempotency: retry returns the original verdict without re-evaluating.
const replay = await db.query(
  `select public.ingest_api_event('${KEY_HASH}', 'evt_test_1', '${CLAUDE}', null,
     'Customer Analysis', array['${CUSTOMERS}'::uuid], null, 'data_access') as r`,
);
const rp = replay.rows[0].r;
const after = await db.query(`select count(*)::int as n from public.ai_requests`);
expect(
  rp.idempotent_replay === true && rp.request_id === r.request_id,
  'retried event_id replays the original verdict',
);
expect(after.rows[0].n === before.rows[0].n + 1, 'replay creates no duplicate request');

// 5. Bad hashes are rejected (deliberately vague).
let badKeyRejected = false;
try {
  await db.query(`select public.ingest_api_event('${'0'.repeat(32)}', 'evt_x', '${CLAUDE}', null, 'x', '{}', null, 'api')`);
} catch (error) {
  badKeyRejected = error.code === '28000';
}
expect(badKeyRejected, 'unknown key hash rejected (28000)');

// 6. Revoked keys stop working.
await db.query(`select public.revoke_api_key('${k.id}')`);
let revokedRejected = false;
try {
  await db.query(`select public.ingest_api_event('${KEY_HASH}', 'evt_x2', '${CLAUDE}', null, 'x', '{}', null, 'api')`);
} catch (error) {
  revokedRejected = error.code === '28000';
}
expect(revokedRejected, 'revoked key rejected');

// 7. Expired and wrong-scope keys are rejected.
await db.exec(`
  insert into public.api_keys (organization_id, name, key_hash, key_prefix, scopes, expires_at)
  values ('${ORG}', 'expired', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'dcp_live_aaa', array['ingest'], now() - interval '1 hour'),
         ('${ORG}', 'narrow', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'dcp_live_bbb', array[]::text[], null);
`);
for (const [hash, label] of [
  ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'expired key rejected'],
  ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'key without ingest scope rejected'],
]) {
  let rejected = false;
  try {
    await db.query(`select public.ingest_api_event('${hash}', 'evt_scope', '${CLAUDE}', null, 'x', '{}', null, 'api')`);
  } catch (error) {
    rejected = error.code === '28000';
  }
  expect(rejected, label);
}

// 8. Unknown agents fail closed.
const fresh = await db.query(
  `select public.create_api_key('${ORG}', 'Fresh', array['ingest'], null) as k`,
);
const freshHash = (await db.query(`select key_hash from public.api_keys where id = '${fresh.rows[0].k.id}'`)).rows[0].key_hash;
let unknownAgentFailed = false;
try {
  await db.query(
    `select public.ingest_api_event('${freshHash}', 'evt_agent', '${CLAUDE}', null, 'x', '{}', 'ghost-agent', 'api')`,
  );
} catch (error) {
  unknownAgentFailed = /ai agent not found/.test(error.message);
}
expect(unknownAgentFailed, 'unknown agent name fails closed');

// 9. Models auto-provision by name (conservative: external), then reuse.
const modelsBefore = await db.query(`select count(*)::int as n from public.ai_models`);
const auto = await db.query(
  `select public.ingest_api_event('${freshHash}', 'evt_model', null, 'brand-new-model',
     'Docs lookup', '{}', null, 'data_access') as r`,
);
expect(auto.rows[0].r.decision === 'allow', 'auto-provisioned model evaluates');
const provisioned = await db.query(
  `select is_external, metadata->>'auto_provisioned' as ap from public.ai_models where name = 'brand-new-model'`,
);
expect(
  provisioned.rows.length === 1 && provisioned.rows[0].is_external === true && provisioned.rows[0].ap === 'true',
  'auto-provisioned model is external and marked',
);
await db.query(
  `select public.ingest_api_event('${freshHash}', 'evt_model2', null, 'brand-new-model',
     'Docs lookup', '{}', null, 'data_access')`,
);
const modelsAfter = await db.query(`select count(*)::int as n from public.ai_models`);
expect(modelsAfter.rows[0].n === modelsBefore.rows[0].n + 1, 'second call reuses the provisioned model');

// 10. Named agents resolve; grants still enforced through the shared engine.
const agentCall = await db.query(
  `select public.ingest_api_event('${freshHash}', 'evt_agent_ok', '${CLAUDE}', null,
     'Docs lookup', array['d0000000-0000-4000-8000-000000000003'::uuid],
     (select name from public.ai_agents where id = '${AGENT1}'), 'agent_action') as r`,
);
expect(agentCall.rows[0].r.decision === 'allow', 'permitted agent evaluates normally');
const ungrantedCall = await db.query(
  `select public.ingest_api_event('${freshHash}', 'evt_agent_denied', '${CLAUDE}', null,
     'Support triage', array['${CUSTOMERS}'::uuid],
     (select name from public.ai_agents where id = '${AGENT2}'), 'agent_action') as r`,
);
expect(
  ungrantedCall.rows[0].r.decision === 'block' && ungrantedCall.rows[0].r.checks.permission === false,
  'agent without a grant is hard-blocked through the API',
);

if (process.exitCode) console.error('API key verification FAILED');
else console.log('API key verification passed');
