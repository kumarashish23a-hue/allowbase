// Verifies migration 023 (gateway API-key scope + verify_api_key RPC) against PGlite.
// Run: node scripts/verify-gateway-keys.mjs
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
console.log('ok   all migrations apply (incl. 023_gateway_api_keys.sql)');

// Seeded by 009_seed.sql.
const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ADMIN = 'b0000000-0000-4000-8000-0000000000a2';
const VIEWER = 'b0000000-0000-4000-8000-0000000000b3';

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

// PGlite stubs pgcrypto's digest(), so the stored hash is NOT a real SHA-256.
// Read it back from the database instead of computing it (same approach as
// verify-api-keys.mjs).
async function storedHash(keyId) {
  const r = await db.query(`select key_hash from public.api_keys where id = '${keyId}'`);
  return r.rows[0].key_hash;
}

await asUser(ADMIN, 'admin');

// 1. Minting with the 'gateway' scope works.
const gw = await db.query(
  `select public.create_api_key('${ORG}', 'Gateway svc', array['gateway'], null) as k`,
);
expect(gw.rows[0].k.key.startsWith('dcp_live_'), 'create_api_key accepts the gateway scope');
const gwHash = await storedHash(gw.rows[0].k.id);
const gwStored = await db.query(`select scopes from public.api_keys where id = '${gw.rows[0].k.id}'`);
expect(gwStored.rows[0].scopes.includes('gateway'), 'gateway scope persisted');

// 2. Combined scopes work.
const both = await db.query(
  `select public.create_api_key('${ORG}', 'Both', array['ingest','gateway'], null) as k`,
);
expect(both.rows[0].k.key.startsWith('dcp_live_'), 'create_api_key accepts ingest+gateway scopes');

// 3. Unknown scopes are still rejected.
let unknownRejected = false;
try {
  await db.query(`select public.create_api_key('${ORG}', 'Bad', array['nope'], null)`);
} catch (error) {
  unknownRejected = /unknown scope/.test(error.message);
}
expect(unknownRejected, 'unknown scope rejected');

// 4. Empty scope list is rejected.
let emptyRejected = false;
try {
  await db.query(`select public.create_api_key('${ORG}', 'Empty', array[]::text[], null)`);
} catch (error) {
  emptyRejected = /unknown scope/.test(error.message);
}
expect(emptyRejected, 'empty scope list rejected');

// 5. verify_api_key authenticates a gateway key for the gateway scope.
const verified = await db.query(`select public.verify_api_key('${gwHash}', 'gateway') as v`);
expect(
  verified.rows[0].v.organization_id === ORG && verified.rows[0].v.key_id === gw.rows[0].k.id,
  'verify_api_key returns key_id + organization_id',
);
const touched = await db.query(`select last_used_at from public.api_keys where id = '${gw.rows[0].k.id}'`);
expect(touched.rows[0].last_used_at !== null, 'verify_api_key touches last_used_at');

// 6. A gateway-scoped key is rejected for the ingest scope (scope isolation).
let scopeIsolated = false;
try {
  await db.query(`select public.verify_api_key('${gwHash}', 'ingest')`);
} catch (error) {
  scopeIsolated = error.code === '28000';
}
expect(scopeIsolated, 'gateway key rejected for ingest scope (28000)');

// 7. Unknown hashes are rejected vaguely.
let unknownRejected2 = false;
try {
  await db.query(`select public.verify_api_key('${'0'.repeat(64)}', 'gateway')`);
} catch (error) {
  unknownRejected2 = error.code === '28000';
}
expect(unknownRejected2, 'unknown key hash rejected (28000)');

// 8. Revoked keys stop verifying.
await db.query(`select public.revoke_api_key('${gw.rows[0].k.id}')`);
let revokedRejected = false;
try {
  await db.query(`select public.verify_api_key('${gwHash}', 'gateway')`);
} catch (error) {
  revokedRejected = error.code === '28000';
}
expect(revokedRejected, 'revoked key rejected (28000)');

// 9. Expired keys stop verifying.
const exp = await db.query(
  `select public.create_api_key('${ORG}', 'Short-lived', array['gateway'], now() + interval '1 hour') as k`,
);
const expHash = await storedHash(exp.rows[0].k.id);
await db.exec(`update public.api_keys set expires_at = now() - interval '1 minute' where id = '${exp.rows[0].k.id}'`);
let expiredRejected = false;
try {
  await db.query(`select public.verify_api_key('${expHash}', 'gateway')`);
} catch (error) {
  expiredRejected = error.code === '28000';
}
expect(expiredRejected, 'expired key rejected (28000)');

// 10. A combined-scope key verifies for both scopes.
const bothHash = await storedHash(both.rows[0].k.id);
const vIngest = await db.query(`select public.verify_api_key('${bothHash}', 'ingest') as v`);
const vGateway = await db.query(`select public.verify_api_key('${bothHash}', 'gateway') as v`);
expect(
  vIngest.rows[0].v.organization_id === ORG && vGateway.rows[0].v.organization_id === ORG,
  'combined key verifies for both scopes',
);

// 11. Plain members still cannot mint keys.
await asUser(VIEWER, 'viewer');
let viewerBlocked = false;
try {
  await db.query(`select public.create_api_key('${ORG}', 'sneaky', array['gateway'], null)`);
} catch (error) {
  viewerBlocked = error.code === '42501';
}
expect(viewerBlocked, 'viewer cannot mint a gateway key (42501)');

// ---- Migration 024: evaluate_gateway_request wrapper + grant tightening ----

const CLAUDE_MODEL = 'f0000000-0000-4000-8000-000000000002'; // seeded in ORG

// 12. The wrapper authenticates a gateway key and evaluates WITHOUT a user
//     session (auth.uid() is null here) — the app.api_key_id stamp replaces
//     the membership check. This is the exact call the edge function makes.
const wrap = await db.query(
  `select public.evaluate_gateway_request('${bothHash}', '${ORG}', '${CLAUDE_MODEL}', 'wrapper test', '{}', null, 'chat', '[]') as r`,
);
const decision = wrap.rows[0].r.decision;
expect(
  ['allow', 'block', 'review'].includes(decision),
  `evaluate_gateway_request evaluates for a machine key (decision=${decision})`,
);

// 13. The wrapper rejects a key bound to a different organization (28000).
let wrapWrongOrg = false;
try {
  await db.query(
    `select public.evaluate_gateway_request('${bothHash}', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '${CLAUDE_MODEL}', 'x', '{}', null, 'chat', '[]')`,
  );
} catch (error) {
  wrapWrongOrg = error.code === '28000';
}
expect(wrapWrongOrg, 'evaluate_gateway_request rejects cross-org key use (28000)');

// 14. The wrapper rejects a revoked key (28000).
let wrapRevoked = false;
try {
  await db.query(
    `select public.evaluate_gateway_request('${gwHash}', '${ORG}', '${CLAUDE_MODEL}', 'x', '{}', null, 'chat', '[]')`,
  );
} catch (error) {
  wrapRevoked = error.code === '28000';
}
expect(wrapRevoked, 'evaluate_gateway_request rejects revoked key (28000)');

// 15. check_rate_limit is no longer executable by anon/authenticated/PUBLIC.
// (Postgres grants EXECUTE on new functions to PUBLIC by default, and every
// role is implicitly in PUBLIC — revoking only the named roles would not
// have closed the hole.)
const grants = await db.query(`
  select grantee from information_schema.role_routine_grants
  where routine_schema = 'public' and routine_name = 'check_rate_limit'
`);
const grantees = grants.rows.map((r) => r.grantee);
expect(
  grantees.includes('service_role') &&
    !grantees.includes('anon') &&
    !grantees.includes('authenticated') &&
    !grantees.includes('PUBLIC'),
  `check_rate_limit closed to anon/authenticated/PUBLIC (now: ${grantees.join(',') || 'none'})`,
);

// 16. evaluate_gateway_request is executable only by service_role (+ owner).
const wrapGrants = await db.query(`
  select grantee from information_schema.role_routine_grants
  where routine_schema = 'public' and routine_name = 'evaluate_gateway_request'
`);
const wrapGrantees = wrapGrants.rows.map((r) => r.grantee);
expect(
  wrapGrantees.includes('service_role') &&
    !wrapGrantees.includes('anon') &&
    !wrapGrantees.includes('authenticated') &&
    !wrapGrantees.includes('PUBLIC'),
  `evaluate_gateway_request closed to anon/authenticated/PUBLIC (now: ${wrapGrantees.join(',') || 'none'})`,
);

console.log(process.exitCode ? 'FAIL some assertions failed' : 'ok   all gateway key assertions passed');
