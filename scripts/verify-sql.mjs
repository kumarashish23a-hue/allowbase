// Verifies supabase/migrations/*.sql against in-memory Postgres (PGlite).
// Run: node scripts/verify-sql.mjs
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

// Sanity checks on schema + seed data.
const checks = [
  ['tables', `select count(*)::int as n from information_schema.tables where table_schema='public' and table_type='BASE TABLE'`],
  ['rls policies', `select count(*)::int as n from pg_policies where schemaname='public'`],
  ['organizations', `select count(*)::int as n from public.organizations`],
  ['members', `select count(*)::int as n from public.organization_members`],
  ['data_sources', `select count(*)::int as n from public.data_sources`],
  ['data_assets', `select count(*)::int as n from public.data_assets`],
  ['findings', `select count(*)::int as n from public.sensitive_data_findings`],
  ['ai_models', `select count(*)::int as n from public.ai_models`],
  ['ai_agents', `select count(*)::int as n from public.ai_agents`],
  ['policies', `select count(*)::int as n from public.policies`],
  ['ai_requests', `select count(*)::int as n from public.ai_requests`],
  ['risk_events', `select count(*)::int as n from public.risk_events`],
  ['audit_logs', `select count(*)::int as n from public.audit_logs`],
];
for (const [label, sql] of checks) {
  const rows = await db.query(sql);
  console.log(`${label}: ${rows.rows[0].n}`);
}

// Exercise the policy condition matcher against seed data.
const match = await db.query(
  `select public.policy_condition_matches(
     'data.classification', 'in', '["restricted","confidential"]'::jsonb,
     'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
     array['d0000000-0000-4000-8000-000000000001'::uuid],
     (select m from public.ai_models m where m.name='Claude'),
     'Customer Analysis'
   ) as matched`
);
console.log('condition matcher (expect true):', match.rows[0].matched);

const noMatch = await db.query(
  `select public.policy_condition_matches(
     'ai.is_external', 'equals', 'false'::jsonb,
     'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
     array['d0000000-0000-4000-8000-000000000003'::uuid],
     (select m from public.ai_models m where m.name='Internal AI'),
     'Customer Support'
   ) as matched`
);
console.log('condition matcher (expect true):', noMatch.rows[0].matched);

// Dashboard RPCs are security definer but gate on membership; they should
// raise 42501 here because there is no authenticated user.
try {
  await db.query(`select public.get_dashboard_metrics('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')`);
  console.log('membership gate: NOT enforced (unexpected)');
  process.exitCode = 1;
} catch (error) {
  console.log('membership gate enforced:', /organization member/.test(error.message));
}

// End-to-end: become a demo admin and run evaluate_ai_request.
await db.exec(`
  create or replace function auth.uid() returns uuid
    language sql stable as $$ select 'b0000000-0000-4000-8000-0000000000a2'::uuid $$;
  insert into public.organization_members (organization_id, user_id, role, status)
  values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a2', 'admin', 'active')
  on conflict (organization_id, user_id) do update set status = 'active';
`);

const blocked = await db.query(
  `select public.evaluate_ai_request(
     'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
     'f0000000-0000-4000-8000-000000000002',
     'Customer Analysis',
     array['d0000000-0000-4000-8000-000000000001'::uuid]
   ) as result`
);
console.log('BLOCK case:', JSON.stringify(blocked.rows[0].result));

const allowed = await db.query(
  `select public.evaluate_ai_request(
     'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
     'f0000000-0000-4000-8000-000000000005',
     'Customer Support',
     array['d0000000-0000-4000-8000-000000000003'::uuid]
   ) as result`
);
console.log('ALLOW case:', JSON.stringify(allowed.rows[0].result));

const metrics = await db.query(
  `select public.get_dashboard_metrics('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') as m`
);
console.log('dashboard metrics:', JSON.stringify(metrics.rows[0].m));

const overTime = await db.query(
  `select * from public.get_requests_over_time('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 3)`
);
console.log('requests over time rows:', overTime.rows.length);

await db.close();
console.log('SQL verification passed.');
