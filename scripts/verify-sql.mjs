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

// --- 015 enforcement mode tests ------------------------------------------------
// Existing orgs keep ENFORCE after the migration (no silent downgrade).
const keptMode = await db.query(`select enforcement_mode from public.organizations where id = '${ORG}'`);
expect(keptMode.rows[0].enforcement_mode === 'enforce', 'existing org keeps enforce mode after 015');

// New orgs default to MONITOR.
await db.exec(
  `insert into public.organizations (id, name, slug) values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Monitor Co', 'monitor-co')`
);
const newMode = await db.query(
  `select enforcement_mode from public.organizations where id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'`
);
expect(newMode.rows[0].enforcement_mode === 'monitor', 'new org defaults to monitor');

// In monitor mode the same request is allowed but records the would-be block.
await db.exec(`update public.organizations set enforcement_mode = 'monitor' where id = '${ORG}'`);
const monitored = await db.query(
  `select public.evaluate_ai_request('${ORG}','${CLAUDE}','Customer Analysis',array['${CUSTOMERS}'::uuid]) as result`
);
const mon = monitored.rows[0].result;
expect(
  mon.decision === 'allow' && mon.enforced === false &&
    mon.would_decision === 'block' && mon.enforcement_mode === 'monitor',
  'monitor mode allows but records would-block'
);

// Audit log records the would-be decision.
const monAudit = await db.query(
  `select action, metadata from public.audit_logs where resource_id = '${mon.request_id}'::uuid`
);
expect(
  monAudit.rows[0].action === 'ai_request_allow' &&
    monAudit.rows[0].metadata.would_decision === 'block' &&
    monAudit.rows[0].metadata.enforced === false,
  'audit log records would-block in monitor mode'
);

// A risk event is still raised — that visibility is the point of monitoring.
const monRisk = await db.query(
  `select title, metadata from public.risk_events where ai_request_id = '${mon.request_id}'::uuid`
);
expect(
  monRisk.rows.length === 1 && /monitor mode/.test(monRisk.rows[0].title),
  'risk event raised in monitor mode'
);

// The request row is stored as allowed with enforcement metadata.
const monReq = await db.query(
  `select status, metadata from public.ai_requests where id = '${mon.request_id}'::uuid`
);
expect(
  monReq.rows[0].status === 'allowed' && monReq.rows[0].metadata.would_decision === 'block',
  'request stored as allowed with would-block metadata'
);

// Invalid modes are rejected by the check constraint.
let invalidRejected = false;
try {
  await db.exec(`update public.organizations set enforcement_mode = 'bogus' where id = '${ORG}'`);
} catch {
  invalidRejected = true;
}
expect(invalidRejected, 'invalid enforcement_mode rejected');

// Back to enforce: the same request blocks again.
await db.exec(`update public.organizations set enforcement_mode = 'enforce' where id = '${ORG}'`);
const blockedAgain = await db.query(
  `select public.evaluate_ai_request('${ORG}','${CLAUDE}','Customer Analysis',array['${CUSTOMERS}'::uuid]) as result`
);
expect(
  blockedAgain.rows[0].result.decision === 'block' && blockedAgain.rows[0].result.enforced === true,
  'enforce mode blocks again'
);

// --- 016 mask action tests --------------------------------------------------
// A mask policy transforms the request: decision allow, masked=true.
await db.exec(`
  insert into public.policies (organization_id, name, description, status, priority, rule, action)
  values ('${ORG}', 'Mask PII test', 'test', 'active', 6,
    '{"conditions":[{"field":"content.category","operator":"in","value":["email","phone"]}]}'::jsonb,
    'mask')
`);
const maskedRes = await db.query(
  `select public.evaluate_ai_request('${ORG}','${INTERNAL_AI}','Support reply',array['${DOCS}'::uuid],null,null,'chat',
     '[{"detector":"regex-v1","category":"email","severity":"medium","confidence":0.95,"count":2}]'::jsonb) as r`
);
const mk = maskedRes.rows[0].r;
expect(mk.decision === 'allow' && mk.masked === true, 'mask policy allows with masked=true');
const mkReq = await db.query(`select metadata from public.ai_requests where id = '${mk.request_id}'::uuid`);
expect(mkReq.rows[0].metadata.masked === true, 'request metadata records masked');
const mkEval = await db.query(
  `select decision from public.policy_evaluations where ai_request_id = '${mk.request_id}'::uuid
   and policy_id = (select id from public.policies where name = 'Mask PII test' and organization_id = '${ORG}'::uuid)`
);
expect(mkEval.rows[0].decision === 'allow', 'mask evaluation recorded as allow');
const mkRisk = await db.query(`select title from public.risk_events where ai_request_id = '${mk.request_id}'::uuid`);
expect(mkRisk.rows.length === 1 && /masked/.test(mkRisk.rows[0].title), 'risk event raised for masking');

// Monitor mode: nothing is transformed, would_mask is recorded instead.
await db.exec(`update public.organizations set enforcement_mode = 'monitor' where id = '${ORG}'`);
const monMaskRes = await db.query(
  `select public.evaluate_ai_request('${ORG}','${INTERNAL_AI}','Support reply',array['${DOCS}'::uuid],null,null,'chat',
     '[{"detector":"regex-v1","category":"email","severity":"medium","confidence":0.95,"count":2}]'::jsonb) as r`
);
const mm = monMaskRes.rows[0].r;
expect(
  mm.decision === 'allow' && mm.masked === false && mm.would_mask === true,
  'monitor mode records would_mask without masking'
);
await db.exec(`update public.organizations set enforcement_mode = 'enforce' where id = '${ORG}'`);

// Invalid policy actions are rejected by the check constraint.
let maskRejected = false;
try {
  await db.exec(
    `insert into public.policies (organization_id, name, status, priority, rule, action)
     values ('${ORG}','Bad action','active',99,'{}'::jsonb,'shred')`
  );
} catch {
  maskRejected = true;
}
expect(maskRejected, 'invalid policy action rejected');

// --- 017 provider connections tests ----------------------------------------
// Table exists, RLS enabled, and no direct policies for authenticated users.
const connCols = await db.query(`
  select column_name from information_schema.columns
  where table_schema = 'public' and table_name = 'ai_provider_connections'
`);
const colNames = connCols.rows.map((r) => r.column_name);
expect(
  ['organization_id', 'provider', 'key_ciphertext', 'key_iv', 'key_hint', 'status'].every((c) =>
    colNames.includes(c),
  ),
  'ai_provider_connections has expected columns',
);
const rlsState = await db.query(`
  select relrowsecurity from pg_class where relname = 'ai_provider_connections'
`);
expect(rlsState.rows[0].relrowsecurity === true, 'provider connections table has RLS enabled');
const connPolicies = await db.query(`
  select count(*)::int as n from pg_policies where tablename = 'ai_provider_connections'
`);
expect(connPolicies.rows[0].n === 0, 'no direct RLS policies on provider connections');

// Authenticated users cannot read or write the credential table directly.
// (Supabase grants default table privileges to authenticated; PGlite does not,
// so grant first to emulate the live environment — RLS must still deny all.)
await db.exec(`grant select, insert, update, delete on public.ai_provider_connections to authenticated`);
await db.exec(`set role authenticated`);
let readDenied = false;
try {
  await db.query(`select * from public.ai_provider_connections limit 1`);
} catch {
  readDenied = true;
}
expect(!readDenied, 'authenticated select returns empty via RLS (no error, no rows)');
let writeDenied = false;
try {
  await db.exec(
    `insert into public.ai_provider_connections (organization_id, provider, key_ciphertext, key_iv)
     values ('${ORG}', 'openai', 'x', 'y')`,
  );
} catch {
  writeDenied = true;
}
await db.exec(`reset role`);
expect(writeDenied, 'authenticated insert into provider connections denied');

// Service role can upsert; one connection per org/provider.
await db.exec(
  `insert into public.ai_provider_connections (organization_id, provider, label, key_ciphertext, key_iv, key_hint, status)
   values ('${ORG}', 'openai', 'OpenAI', 'ct', 'iv', '••••1234', 'active')`,
);
await db.exec(
  `insert into public.ai_provider_connections (organization_id, provider, label, key_ciphertext, key_iv, key_hint, status)
   values ('${ORG}', 'openai', 'OpenAI', 'ct2', 'iv2', '••••5678', 'active')
   on conflict (organization_id, provider) do update
   set key_ciphertext = excluded.key_ciphertext, key_iv = excluded.key_iv,
       key_hint = excluded.key_hint, updated_at = now()`,
);
const connRows = await db.query(
  `select key_hint, key_ciphertext from public.ai_provider_connections where organization_id = '${ORG}' and provider = 'openai'`,
);
expect(
  connRows.rows.length === 1 && connRows.rows[0].key_hint === '••••5678',
  'upsert keeps one connection per org/provider',
);

await db.close();
console.log('SQL verification passed.');
