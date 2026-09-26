// Verifies supabase/remove_demo_data.sql: applies migrations + seed +
// starter_kit to a fresh org, runs the removal, and asserts the demo rows
// are gone while the Acme org and user-created rows survive.
// Run: node scripts/verify-remove-demo.mjs
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PGlite } from '@electric-sql/pglite';

const dir = new URL('../supabase/', import.meta.url).pathname;
const migDir = join(dir, 'migrations');
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
  sql = sql.replace('create extension if not exists "pgcrypto";', '-- stubbed');
  await db.exec(FALLBACK_UUID + sql);
}

// Simulate a real user org, then load the starter kit into it.
await db.exec(`
  insert into public.organizations (id, name, slug, plan, status)
  values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'User Org', 'user-org', 'startup', 'active');
`);
await db.exec(FALLBACK_UUID + readFileSync(join(dir, 'starter_kit.sql'), 'utf8'));

// The user also creates something of their own that must survive.
await db.exec(`
  insert into public.policies (organization_id, name, description, status, priority, rule, action)
  values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'My Real Policy', 'user-created', 'active', 5, '{}', 'allow');
`);

const count = async (table, org) =>
  (await db.query(`select count(*)::int as c from public.${table} where organization_id = $1`, [org])).rows[0].c;

const before = {
  sources: await count('data_sources', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  policies: await count('policies', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  acmeSources: await count('data_sources', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
  acmePolicies: await count('policies', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
};

// Run the removal script.
await db.exec(FALLBACK_UUID + readFileSync(join(dir, 'remove_demo_data.sql'), 'utf8'));

const after = {
  sources: await count('data_sources', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  assets: await count('data_assets', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  models: await count('ai_models', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  agents: await count('ai_agents', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  policies: await count('policies', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  findings: await count('sensitive_data_findings', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  grants: (await db.query(`select count(*)::int as c from public.ai_agent_data_permissions p join public.ai_agents a on a.id = p.agent_id where a.organization_id = $1`, ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'])).rows[0].c,
  acmeSources: await count('data_sources', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
  acmePolicies: await count('policies', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
  acmeAgents: await count('ai_agents', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
};

let failed = false;
const check = (label, actual, expected) => {
  const ok = actual === expected;
  if (!ok) failed = true;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}: got ${actual}, want ${expected}`);
};

check('user org had 2 demo sources before', before.sources, 2);
check('user org sources removed', after.sources, 0);
check('user org assets removed', after.assets, 0);
check('user org models removed', after.models, 0);
check('user org agents removed', after.agents, 0);
check('user org findings removed', after.findings, 0);
check('user org grants removed', after.grants, 0);
check('user org keeps only its own policy', after.policies, 1);
check('acme sources untouched', after.acmeSources, before.acmeSources);
check('acme policies untouched', after.acmePolicies, before.acmePolicies);
check('acme agents untouched', after.acmeAgents, 4);

// Re-run: must be a safe no-op.
await db.exec(FALLBACK_UUID + readFileSync(join(dir, 'remove_demo_data.sql'), 'utf8'));
check('re-run keeps user policy', await count('policies', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'), 1);

if (failed) process.exit(1);
console.log('remove_demo_data.sql verified.');
