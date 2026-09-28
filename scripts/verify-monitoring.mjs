// Verifies supabase/migrations/022_monitoring.sql against in-memory Postgres (PGlite).
// Follows the pattern of scripts/verify-sql.mjs: applies every migration in
// order (001-019, then 022; 020/021 belong to parallel workstreams and are not
// present), then exercises the monitoring RPCs, aggregations, and RLS policies.
// Run: node scripts/verify-monitoring.mjs
import { existsSync, readdirSync, readFileSync } from 'node:fs';
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
const applied = [];
for (const file of files) {
  const full = join(dir, file);
  if (!existsSync(full)) {
    // Another workstream may be mid-write on its own migration; skip and note.
    console.log(`skip ${file} (not on disk)`);
    continue;
  }
  let sql = readFileSync(full, 'utf8');
  sql = sql.replace('create extension if not exists "pgcrypto";', '-- pgcrypto provided by Supabase; stubbed in verification');
  try {
    await db.exec(FALLBACK_UUID + sql);
    applied.push(file);
    console.log(`ok   ${file}`);
  } catch (error) {
    failed = true;
    console.error(`FAIL ${file}: ${error.message}`);
  }
}
if (failed) process.exit(1);
if (!applied.includes('022_monitoring.sql')) {
  console.error('FAIL 022_monitoring.sql was not applied (missing from migrations dir)');
  process.exit(1);
}

const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ADMIN = 'b0000000-0000-4000-8000-0000000000a2';

function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) process.exitCode = 1;
}

// --- (a) record_function_metric ------------------------------------------------
await db.exec(`select public.record_function_metric('ingest-event', '${ORG}'::uuid, 'ok', 42, null)`);
const inserted = await db.query(`select count(*)::int as n from public.function_metrics`);
expect(inserted.rows[0].n === 1, 'record_function_metric inserts a row');

let invalidRejected = false;
try {
  await db.exec(`select public.record_function_metric('ingest-event', '${ORG}'::uuid, 'bogus', 1, null)`);
} catch (error) {
  invalidRejected = /invalid metric status/.test(error.message);
}
expect(invalidRejected, 'record_function_metric rejects an invalid status');
const stillOne = await db.query(`select count(*)::int as n from public.function_metrics`);
expect(stillOne.rows[0].n === 1, 'invalid insert left no row behind');

// --- (b) aggregation queries on seeded metrics ---------------------------------
// Seed 10 rows: total 10, errors 2, rate_limited 1, one ai-gateway error,
// latencies 30..110 plus a 5000 outlier.
await db.exec(`delete from public.function_metrics`);
const seed = [
  ['ingest-event', 'ok', 50, null],
  ['ingest-event', 'ok', 60, null],
  ['ingest-event', 'ok', 70, null],
  ['ingest-event', 'ok', 80, null],
  ['evaluate-ai-request', 'ok', 90, null],
  ['evaluate-ai-request', 'error', 100, 'ERR_X'],
  ['ai-gateway', 'ok', 110, null],
  ['ai-gateway', 'error', 5000, 'GATEWAY_DOWN'],
  ['ingest-event', 'rate_limited', 30, 'RATE_LIMIT'],
  ['evaluate-ai-request', 'ok', 40, null],
];
for (const [fn, status, latency, code] of seed) {
  await db.exec(
    `select public.record_function_metric('${fn}', '${ORG}'::uuid, '${status}', ${latency}, ${code ? `'${code}'` : 'null'})`,
  );
}

async function makeRule(name, metric, threshold, windowMinutes = 60) {
  const res = await db.query(
    `insert into public.alert_rules (organization_id, name, metric, threshold, window_minutes)
     values ('${ORG}'::uuid, '${name}', '${metric}', ${threshold}, ${windowMinutes})
     returning id`,
  );
  return res.rows[0].id;
}
async function check(ruleId) {
  const res = await db.query(`select public.check_alert_rule('${ruleId}'::uuid) as r`);
  return res.rows[0].r;
}

// error_rate: 2/10 = 0.2 > 0.1 -> breach, fires as critical.
const r1 = await makeRule('Error spike', 'error_rate', 0.1);
const c1 = await check(r1);
expect(
  c1.checked === true && c1.breached === true && Math.abs(Number(c1.value) - 0.2) < 1e-9 && c1.fired === true,
  'error_rate computes 0.2 and fires on breach',
);
const a1 = await db.query(`select severity, message from public.alerts where rule_id = '${r1}'::uuid`);
expect(
  a1.rows.length === 1 && a1.rows[0].severity === 'critical' && a1.rows[0].message.includes('Error spike'),
  'breaching error_rate fires a critical alert naming the rule',
);

// p95_latency_ms: percentile_cont(0.95) over 10 rows = 110 + 0.55*(5000-110) = 2799.5.
const r2 = await makeRule('Slow functions', 'p95_latency_ms', 100);
const c2 = await check(r2);
expect(
  c2.breached === true && Math.abs(Number(c2.value) - 2799.5) < 0.01 && c2.fired === true,
  'p95_latency_ms computes ~2799.5 and fires on breach',
);
const a2 = await db.query(`select severity from public.alerts where rule_id = '${r2}'::uuid`);
expect(a2.rows[0].severity === 'warning', 'p95 breach fires as warning');

// denial_rate: 1/10 = 0.1, threshold 0.5 -> no breach.
const r3 = await makeRule('Rate limit storm', 'denial_rate', 0.5);
const c3 = await check(r3);
expect(
  c3.breached === false && Math.abs(Number(c3.value) - 0.1) < 1e-9 && c3.fired === false && c3.resolved === false,
  'denial_rate computes 0.1 and does not breach a 0.5 threshold',
);

// provider_failures: 1 ai-gateway error > 0 -> breach, fires as critical.
const r4 = await makeRule('Gateway down', 'provider_failures', 0);
const c4 = await check(r4);
expect(
  c4.breached === true && Number(c4.value) === 1 && c4.fired === true,
  'provider_failures counts 1 ai-gateway error and fires on breach',
);
const a4 = await db.query(`select severity from public.alerts where rule_id = '${r4}'::uuid`);
expect(a4.rows[0].severity === 'critical', 'provider_failures breach fires as critical');

// Re-checking a breaching rule does not duplicate the firing alert.
const c1b = await check(r1);
expect(c1b.fired === false, 'repeat breach check does not duplicate the firing alert');
const a1b = await db.query(
  `select count(*)::int as n from public.alerts where rule_id = '${r1}'::uuid and status = 'firing'`,
);
expect(a1b.rows[0].n === 1, 'exactly one firing alert per rule');

// A non-breaching rule resolves its existing firing alert.
const r5 = await makeRule('Quiet error rule', 'error_rate', 0.99);
await db.exec(
  `insert into public.alerts (rule_id, organization_id, message, severity)
   values ('${r5}'::uuid, '${ORG}'::uuid, 'stale firing alert', 'warning')`,
);
const c5 = await check(r5);
expect(c5.breached === false && c5.resolved === true, 'non-breaching rule resolves its firing alert');
const a5 = await db.query(`select status, resolved_at from public.alerts where rule_id = '${r5}'::uuid`);
expect(a5.rows[0].status === 'resolved' && a5.rows[0].resolved_at !== null, 'resolved alert carries resolved_at');

// Total=0 guard: a rule on an org with no metrics never breaches.
await db.exec(
  `insert into public.organizations (id, name, slug) values ('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'Empty Co', 'empty-co-x')
   on conflict (id) do nothing`,
);
const r6res = await db.query(
  `insert into public.alert_rules (organization_id, name, metric, threshold, window_minutes)
   values ('cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid, 'Empty error rate', 'error_rate', 0.01, 60)
   returning id`,
);
const c6 = await check(r6res.rows[0].id);
expect(c6.breached === false && c6.fired === false, 'empty window never breaches (total=0 guard)');

// Inactive rules are skipped.
const r7 = await makeRule('Paused rule', 'error_rate', 0.01);
await db.exec(`update public.alert_rules set is_active = false where id = '${r7}'::uuid`);
const c7 = await check(r7);
expect(c7.checked === false, 'inactive rule is not checked');

// --- (c) RLS policies -----------------------------------------------------------
const rlsState = await db.query(`
  select relname, relrowsecurity from pg_class
  where relname in ('function_metrics', 'alert_rules', 'alerts')
`);
expect(rlsState.rows.length === 3 && rlsState.rows.every((r) => r.relrowsecurity === true), 'RLS enabled on all three tables');

const metricCmds = await db.query(`
  select cmd from pg_policies where schemaname = 'public' and tablename = 'function_metrics'
`);
expect(
  metricCmds.rows.length === 1 && metricCmds.rows[0].cmd === 'SELECT',
  'function_metrics has SELECT-only policy (no insert/update/delete)',
);

const alertCmds = await db.query(`
  select count(*)::int as n from pg_policies
  where schemaname = 'public' and tablename = 'alerts'
`);
expect(alertCmds.rows[0].n === 1, 'alerts has a single SELECT policy (no direct writes)');

for (const cmd of ['INSERT', 'UPDATE', 'DELETE']) {
  const gated = await db.query(
    `select count(*)::int as n from pg_policies
     where schemaname = 'public' and tablename = 'alert_rules' and cmd = '${cmd}'
       and (qual like '%has_org_role%' or with_check like '%has_org_role%')`,
  );
  expect(gated.rows[0].n >= 1, `alert_rules ${cmd} policy is owner/admin-gated`);
}
const ruleSelect = await db.query(
  `select count(*)::int as n from pg_policies
   where schemaname = 'public' and tablename = 'alert_rules' and cmd = 'SELECT' and qual like '%is_org_member%'`,
);
expect(ruleSelect.rows[0].n === 1, 'alert_rules SELECT policy is member-scoped');

// RLS behavior: an org member reads only their org's rows; NULL-org rows are
// invisible; direct writes are denied even with table privileges granted
// (emulating Supabase's default grants, where RLS is the only gate).
await db.exec(`
  create or replace function auth.uid() returns uuid
    language sql stable as $$ select '${ADMIN}'::uuid $$;
  insert into public.organization_members (organization_id, user_id, role, status)
  values ('${ORG}'::uuid, '${ADMIN}'::uuid, 'admin', 'active')
  on conflict (organization_id, user_id) do update set status = 'active', role = 'admin';
  insert into public.function_metrics (function_name, organization_id, status, latency_ms)
  values ('ingest-event', null, 'ok', 5);
  grant select, insert, update, delete on public.function_metrics to authenticated;
`);
await db.exec(`set role authenticated`);
const visible = await db.query(`select count(*)::int as n from public.function_metrics`);
expect(visible.rows[0].n === 10, 'member select sees only their org rows (NULL-org row hidden)');
// INSERT with no policy raises; UPDATE/DELETE silently touch zero rows.
let insertDenied = false;
try {
  await db.exec(`insert into public.function_metrics (function_name, status, latency_ms) values ('x', 'ok', 1)`);
} catch {
  insertDenied = true;
}
const before = (await db.query(`select count(*)::int as n, coalesce(sum(latency_ms), 0)::int as s from public.function_metrics`)).rows[0];
await db.exec(`update public.function_metrics set latency_ms = 1`);
await db.exec(`delete from public.function_metrics`);
const after = (await db.query(`select count(*)::int as n, coalesce(sum(latency_ms), 0)::int as s from public.function_metrics`)).rows[0];
await db.exec(`reset role`);
expect(
  insertDenied && before.n === after.n && before.s === after.s,
  'authenticated insert denied; update/delete touch no rows',
);

await db.close();
console.log('Monitoring verification passed.');
