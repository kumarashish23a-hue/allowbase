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
     'Customer Analysis',
     '[]'::jsonb
   ) as matched`
);
console.log('condition matcher (expect true):', match.rows[0].matched);

const noMatch = await db.query(
  `select public.policy_condition_matches(
     'ai.is_external', 'equals', 'false'::jsonb,
     'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
     array['d0000000-0000-4000-8000-000000000003'::uuid],
     (select m from public.ai_models m where m.name='Internal AI'),
     'Customer Support',
     '[]'::jsonb
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
  on conflict (organization_id, user_id) do update set status = 'active', role = 'admin';
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

// --- 010 hardening tests -------------------------------------------------------
const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ADMIN = 'b0000000-0000-4000-8000-0000000000a2';
const MEMBER = 'b0000000-0000-4000-8000-0000000000b3';
const CLAUDE = 'f0000000-0000-4000-8000-000000000002';
const INTERNAL_AI = 'f0000000-0000-4000-8000-000000000005';
const CUSTOMERS = 'd0000000-0000-4000-8000-000000000001';
const TICKETS = 'd0000000-0000-4000-8000-000000000002';
const DOCS = 'd0000000-0000-4000-8000-000000000003';
const AGENT1 = '10000000-0000-4000-8000-000000000001';
const AGENT2 = '10000000-0000-4000-8000-000000000002';

function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) process.exitCode = 1;
}

// 1. Agent without a grant -> hard block (default deny for agents).
const agentBlocked = await db.query(
  `select public.evaluate_ai_request('${ORG}','${CLAUDE}','Support triage',array['${CUSTOMERS}'::uuid],null,'${AGENT2}','agent_action') as r`
);
const ab = agentBlocked.rows[0].r;
expect(
  ab.decision === 'block' &&
    ab.checks.permission === false &&
    ab.policies_triggered.includes('Agent data permission check') &&
    /no read permission/.test(ab.reasons.join(' ')),
  'agent without grant is blocked'
);

// 2. Agent with a grant -> permission passes, policy still decides.
const agentOk = await db.query(
  `select public.evaluate_ai_request('${ORG}','${CLAUDE}','Docs lookup',array['${DOCS}'::uuid],null,'${AGENT1}','agent_action') as r`
);
const ao = agentOk.rows[0].r;
expect(ao.decision === 'allow' && ao.checks.permission === true, 'agent with grant is evaluated normally');

// 3. Cross-org asset id -> exception (fail closed).
await db.exec(`
  insert into public.organizations (id, name, slug)
  values ('bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb', 'Other', 'other-x')
  on conflict (id) do nothing;
  insert into public.data_assets (id, organization_id, name, asset_type)
  values ('e0000000-0000-4000-8000-000000000001', 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb', 'other_secret', 'table')
  on conflict (id) do nothing;
`);
let crossOrgFailed = false;
try {
  await db.query(
    `select public.evaluate_ai_request('${ORG}','${CLAUDE}','x',array['e0000000-0000-4000-8000-000000000001'::uuid])`
  );
} catch (error) {
  crossOrgFailed = /not found in organization/.test(error.message);
}
expect(crossOrgFailed, 'cross-org asset id is rejected');

// 4. require_approval policy -> pending_approval + approval row.
await db.exec(`
  insert into public.policies (organization_id, name, status, priority, rule, action)
  values ('${ORG}', 'Medium data needs approval', 'active', 30,
    '{"conditions": [{"field": "data.sensitivity_level", "operator": "equals", "value": "medium"}]}',
    'require_approval')
`);
const appr = await db.query(
  `select public.evaluate_ai_request('${ORG}','${INTERNAL_AI}','Ticket analysis',array['${TICKETS}'::uuid]) as r`
);
const ar = appr.rows[0].r;
expect(
  ar.decision === 'review' && ar.approval_required === true && ar.approval_request_id,
  'require_approval opens a pending approval'
);
const reqStatus = await db.query(`select status from public.ai_requests where id = '${ar.request_id}'::uuid`);
expect(reqStatus.rows[0].status === 'pending_approval', 'request status is pending_approval');
const apprRow = await db.query(
  `select status from public.approval_requests where id = '${ar.approval_request_id}'::uuid`
);
expect(apprRow.rows[0].status === 'pending', 'approval row is pending');

// 5. Admin approves -> request allowed + audited.
const decided = await db.query(
  `select public.decide_approval('${ar.approval_request_id}'::uuid, 'approved', 'looks fine') as d`
);
expect(decided.rows[0].d.request_status === 'allowed', 'approval moves request to allowed');
const auditRow = await db.query(`select count(*)::int as n from public.audit_logs where action = 'approval_approved'`);
expect(auditRow.rows[0].n === 1, 'approval decision is audited');

// 6. Non-admin member cannot decide approvals.
await db.exec(`
  insert into public.organization_members (organization_id, user_id, role, status)
  values ('${ORG}', '${MEMBER}', 'viewer', 'active')
  on conflict (organization_id, user_id) do update set role = 'viewer', status = 'active';
  create or replace function auth.uid() returns uuid
    language sql stable as $$ select '${MEMBER}'::uuid $$;
`);
const appr2 = await db.query(
  `select public.evaluate_ai_request('${ORG}','${INTERNAL_AI}','More tickets',array['${TICKETS}'::uuid]) as r`
);
let memberDenied = false;
try {
  await db.query(`select public.decide_approval('${appr2.rows[0].r.approval_request_id}'::uuid, 'approved')`);
} catch (error) {
  memberDenied = /only organization owners or admins/.test(error.message);
}
expect(memberDenied, 'non-admin cannot decide approvals');

await db.close();
console.log('SQL verification passed.');
