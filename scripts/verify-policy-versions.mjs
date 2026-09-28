// Verifies supabase/migrations/021_policy_versions.sql (policy versioning +
// rollback) against in-memory Postgres (PGlite).
// Run: node scripts/verify-policy-versions.mjs
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PGlite } from '@electric-sql/pglite';

const dir = new URL('../supabase/migrations/', import.meta.url).pathname;
const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();

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

// Supabase-provided roles.
await db.exec(`
  do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon; end if;
    if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated; end if;
    if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role; end if;
  end $$;
`);

// PGlite has no pgcrypto: strip the extension line and provide a fallback
// gen_random_uuid() for verification only. Real Supabase always has pgcrypto.
const FALLBACK_UUID = `
  create or replace function public.gen_random_uuid() returns uuid
  language sql as $$ select md5(random()::text || clock_timestamp()::text)::uuid $$;
`;

let failed = false;
for (const file of files) {
  let sql = readFileSync(join(dir, file), 'utf8');
  sql = sql.replace('create extension if not exists "pgcrypto";', '-- pgcrypto provided by Supabase; stubbed in verification');
  try {
    await db.exec(FALLBACK_UUID + sql);
    console.log(`ok   ${file}`);
  } catch (error) {
    failed = true;
    console.error(`FAIL ${file}: ${error.message}`);
  }
}
if (failed) process.exit(1);

const OWNER = 'c1000000-0000-4000-8000-000000000001';
const STRANGER = 'c1000000-0000-4000-8000-000000000002';
const ORG = 'c2000000-0000-4000-8000-000000000001';

function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) process.exitCode = 1;
}

// Become an owner of a fresh org.
await db.exec(`
  create or replace function auth.uid() returns uuid
    language sql stable as $$ select '${OWNER}'::uuid $$;
  insert into auth.users (id, email) values ('${OWNER}', 'owner@example.com'), ('${STRANGER}', 'stranger@example.com');
  insert into public.organizations (id, name, slug) values ('${ORG}', 'Version Co', 'version-co');
  insert into public.organization_members (organization_id, user_id, role, status)
  values ('${ORG}', '${OWNER}', 'owner', 'active');
`);

async function snapshotVersions(policyId) {
  const rows = await db.query(
    `select version, name, change_note from public.policy_versions where policy_id = '${policyId}' order by version`
  );
  return rows.rows;
}

// (a) INSERT policy -> version = 1 and exactly one snapshot.
const created = await db.query(`
  insert into public.policies (organization_id, name, description, status, priority, rule, action)
  values ('${ORG}', 'Block PII leaks', 'v1 description', 'active', 10,
          '{"conditions": []}'::jsonb, 'block')
  returning id, version
`);
const policyId = created.rows[0].id;
expect(created.rows[0].version === 1, 'insert sets version = 1');
let snaps = await snapshotVersions(policyId);
expect(snaps.length === 1 && snaps[0].version === 1 && snaps[0].name === 'Block PII leaks', 'insert writes one v1 snapshot');

// (b) UPDATE name -> version = 2, two snapshots, v1 keeps the old name.
await db.exec(`update public.policies set name = 'Block PII leaks (tightened)' where id = '${policyId}'`);
const after = await db.query(`select version from public.policies where id = '${policyId}'`);
snaps = await snapshotVersions(policyId);
expect(
  after.rows[0].version === 2 &&
    snaps.length === 2 &&
    snaps[0].name === 'Block PII leaks' &&
    snaps[1].name === 'Block PII leaks (tightened)',
  'name update bumps to v2; v1 snapshot keeps old name'
);

// (c) Touching only updated_at must NOT bump the version.
await db.exec(`update public.policies set updated_at = now() where id = '${policyId}'`);
const afterTouch = await db.query(`select version from public.policies where id = '${policyId}'`);
snaps = await snapshotVersions(policyId);
expect(afterTouch.rows[0].version === 2 && snaps.length === 2, 'updated_at-only touch leaves version at 2');

// (d) rollback to v1 -> returns 3, name restored, snapshot count grows (append-only).
const rolled = await db.query(`select public.rollback_policy('${policyId}', 1, 'test rollback') as v`);
snaps = await snapshotVersions(policyId);
const restored = await db.query(`select name, description, version from public.policies where id = '${policyId}'`);
expect(
  rolled.rows[0].v === 3 &&
    restored.rows[0].name === 'Block PII leaks' &&
    restored.rows[0].description === 'v1 description' &&
    restored.rows[0].version === 3 &&
    snaps.length === 3 &&
    snaps[2].change_note === 'test rollback',
  'rollback to v1 returns 3, restores fields, appends snapshot with note'
);

// (e) rollback by a non-member raises not_authorized.
await db.exec(`
  create or replace function auth.uid() returns uuid
    language sql stable as $$ select '${STRANGER}'::uuid $$;
`);
let notAuthorized = false;
try {
  await db.query(`select public.rollback_policy('${policyId}', 1, 'evil')`);
} catch (error) {
  notAuthorized = /not_authorized/.test(error.message);
}
expect(notAuthorized, 'rollback by non-member raises not_authorized');

// (f) policy_versions has a select policy but no insert/update/delete policies (append-only).
const writePolicies = await db.query(`
  select cmd from pg_policies
  where schemaname = 'public' and tablename = 'policy_versions' and cmd <> 'SELECT'
`);
const selectPolicies = await db.query(`
  select policyname from pg_policies
  where schemaname = 'public' and tablename = 'policy_versions' and cmd = 'SELECT'
`);
expect(writePolicies.rows.length === 0, 'no insert/update/delete policies on policy_versions');
expect(selectPolicies.rows.length === 1, 'one select policy on policy_versions');

if (process.exitCode === 1) {
  console.error('policy versioning verification FAILED');
  process.exit(1);
}
console.log('policy versioning verification passed');
