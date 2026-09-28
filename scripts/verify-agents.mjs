// Verifies Phase G (agent guardrails):
//   Part 1 — unit tests for supabase/functions/_shared/agentGuard.ts
//   (transpiled with the project's TypeScript, run in Node): canonical arg
//   hashing, trailing-run loop counting, guardrail verdict parsing.
//   Part 2 — migration 030 against in-memory Postgres (PGlite):
//   check_agent_guardrails — inactive agents, blocklist/allowlist, tool-risk
//   vs agent-risk escalation, per-agent approval requirements, hourly
//   call/volume caps, loop detection with run-breaking, risk events on
//   anomaly-class violations only, and agent_tool_calls RLS.
// Run: node scripts/verify-agents.mjs
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

// --- Part 1: pure module -------------------------------------------------------
const require = createRequire(join(process.cwd(), 'package.json'));
const ts = require('typescript');
const dir = join(tmpdir(), 'dataplane-agents-test');
mkdirSync(dir, { recursive: true });

const src = readFileSync('supabase/functions/_shared/agentGuard.ts', 'utf8');
const { outputText, diagnostics } = ts.transpileModule(src, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
  reportDiagnostics: true,
});
const fatal = (diagnostics ?? []).filter((d) => d.category === ts.DiagnosticCategory.Error);
if (fatal.length > 0) {
  console.error('TypeScript errors in agentGuard.ts:');
  for (const d of fatal) console.error(' -', ts.flattenDiagnosticMessageText(d.messageText, ' '));
  process.exit(1);
}
const out = join(dir, 'agentGuard.mjs');
writeFileSync(out, outputText);
const G = await import(pathToFileURL(out).href);

expect(G.AGENT_GUARD_VERSION === 'agent-v1', 'guard version stamped');

// canonicalize: key order independent, nested, arrays ordered.
{
  expect(
    G.canonicalize({ b: 1, a: 2 }) === G.canonicalize({ a: 2, b: 1 }),
    'canonicalize ignores key order',
  );
  expect(
    G.canonicalize({ x: { d: 4, c: 3 } }) === '{"x":{"c":3,"d":4}}',
    'canonicalize sorts nested keys',
  );
  expect(G.canonicalize([3, 1, 2]) === '[3,1,2]', 'canonicalize preserves array order');
  expect(G.canonicalize(null) === 'null', 'canonicalize handles null');
}

// hashArguments: deterministic, 64-hex, order independent, sensitive to change.
{
  const h1 = await G.hashArguments({ table: 'users', limit: 10 });
  const h2 = await G.hashArguments({ limit: 10, table: 'users' });
  const h3 = await G.hashArguments({ table: 'users', limit: 11 });
  expect(/^[0-9a-f]{64}$/.test(h1), 'hash is 64 hex chars');
  expect(h1 === h2, 'hash ignores key order');
  expect(h1 !== h3, 'hash changes with the arguments');
}

// trailingIdenticalRun: counts the trailing run, breaks on divergence.
{
  const recent = [
    { toolName: 'get_user', argsHash: 'aa' },
    { toolName: 'get_user', argsHash: 'aa' },
    { toolName: 'get_user', argsHash: 'bb' },
    { toolName: 'get_user', argsHash: 'aa' },
  ];
  expect(G.trailingIdenticalRun(recent, 'get_user', 'aa') === 2, 'counts trailing identical run');
  expect(G.trailingIdenticalRun(recent, 'get_user', 'bb') === 0, 'non-matching head -> 0');
  expect(G.trailingIdenticalRun([], 'get_user', 'aa') === 0, 'empty history -> 0');
}

// parseGuardVerdict: shape-checks the SQL verdict.
{
  const v = G.parseGuardVerdict({ decision: 'allow', force_approval: true, reasons: ['x'], escalation: false });
  expect(v.decision === 'allow' && v.forceApproval === true && v.reasons[0] === 'x', 'parses a valid verdict');
  expect(G.guardForcesApproval(v) === true, 'force approval detected');
  let threw = 0;
  try { G.parseGuardVerdict({ decision: 'maybe' }); } catch { threw++; }
  try { G.parseGuardVerdict(null); } catch { threw++; }
  try { G.parseGuardVerdict('allow'); } catch { threw++; }
  expect(threw === 3, 'malformed verdicts throw');
}

// --- Part 2: migration 030 in PGlite ------------------------------------------
const migDir = new URL('../supabase/migrations/', import.meta.url).pathname;
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
console.log('ok   all migrations incl. 030 apply');

// Supabase grants anon/authenticated default table access; PGlite needs it explicit.
await db.exec(`
  grant select, insert, update, delete on public.agent_tool_calls to authenticated;
  grant select, insert, update, delete on public.ai_agents to authenticated;
  grant select, insert, update, delete on public.risk_events to authenticated;
`);

const ORG = 'e0000000-0000-4000-8000-000000000001';
const OWNER = 'e0000000-0000-4000-8000-0000000000a1';
const A_ALLOW = 'e0000000-0000-4000-8000-0000000000b1';
const A_PAUSED = 'e0000000-0000-4000-8000-0000000000b2';
const A_BLOCKED = 'e0000000-0000-4000-8000-0000000000b3';
const A_APPROVE_ALL = 'e0000000-0000-4000-8000-0000000000b4';
const A_LIMIT = 'e0000000-0000-4000-8000-0000000000b5';
const A_VOLUME = 'e0000000-0000-4000-8000-0000000000b6';
const A_LOOP = 'e0000000-0000-4000-8000-0000000000b7';
const A_RISK = 'e0000000-0000-4000-8000-0000000000b8';

await db.exec(`
  insert into auth.users (id, email) values ('${OWNER}', 'owner@x.test');
  create or replace function auth.uid() returns uuid language sql stable as $$ select '${OWNER}'::uuid $$;
  insert into public.organizations (id, name, slug) values ('${ORG}', 'Agent Org', 'agent-org');
  insert into public.organization_members (organization_id, user_id, role, status)
  values ('${ORG}', '${OWNER}', 'owner', 'active');
  insert into public.ai_agents (id, organization_id, name, status, risk_level, allowed_tools, max_tool_calls_per_hour)
  values ('${A_ALLOW}', '${ORG}', 'allow-agent', 'active', 'medium', '{get_user}', 100);
  insert into public.ai_agents (id, organization_id, name, status, risk_level)
  values ('${A_PAUSED}', '${ORG}', 'paused-agent', 'paused', 'medium');
  insert into public.ai_agents (id, organization_id, name, status, risk_level, blocked_tools)
  values ('${A_BLOCKED}', '${ORG}', 'blocked-agent', 'active', 'medium', '{delete_rows}');
  insert into public.ai_agents (id, organization_id, name, status, risk_level, approval_required_for)
  values ('${A_APPROVE_ALL}', '${ORG}', 'approve-agent', 'active', 'high', '{*}');
  insert into public.ai_agents (id, organization_id, name, status, risk_level, max_tool_calls_per_hour)
  values ('${A_LIMIT}', '${ORG}', 'limit-agent', 'active', 'medium', 2);
  insert into public.ai_agents (id, organization_id, name, status, risk_level, max_data_bytes_per_hour)
  values ('${A_VOLUME}', '${ORG}', 'volume-agent', 'active', 'medium', 100);
  insert into public.ai_agents (id, organization_id, name, status, risk_level)
  values ('${A_LOOP}', '${ORG}', 'loop-agent', 'active', 'medium');
  insert into public.ai_agents (id, organization_id, name, status, risk_level)
  values ('${A_RISK}', '${ORG}', 'risk-agent', 'active', 'low');
`);

async function guard(agent, tool, risk, hash, bytes) {
  const res = await db.query(
    `select public.check_agent_guardrails('${ORG}'::uuid, '${agent}'::uuid, '${tool}', '${risk}', '${hash}', ${bytes}) as v`,
  );
  return res.rows[0].v;
}

// 1. Inactive agent: blocked, no escalation, no risk event.
{
  const v = await guard(A_PAUSED, 'get_user', 'low', 'aa', 10);
  expect(v.decision === 'block' && v.reasons[0].includes('paused'), 'paused agent is blocked');
  expect(v.escalation === false, 'paused agent is not an escalation');
}

// 2. Blocked tool: block + escalation + risk event.
{
  const before = (await db.query(`select count(*)::int as n from public.risk_events where organization_id = '${ORG}'`)).rows[0].n;
  const v = await guard(A_BLOCKED, 'delete_rows', 'high', 'bb', 10);
  expect(v.decision === 'block' && v.escalation === true, 'blocked tool -> block + escalation');
  const after = (await db.query(`select count(*)::int as n from public.risk_events where organization_id = '${ORG}'`)).rows[0].n;
  expect(after === before + 1, 'escalation creates a risk event');
  const ev = (await db.query(`select title, severity, metadata from public.risk_events where organization_id = '${ORG}' order by created_at desc limit 1`)).rows[0];
  expect(ev.severity === 'high' && ev.metadata.guardrail === 'agent-v1' && ev.metadata.tool_name === 'delete_rows', 'risk event carries counts/identity only');
}

// 3. Allowlist: listed tool allowed, unlisted blocked + escalation.
{
  const v1 = await guard(A_ALLOW, 'get_user', 'low', 'cc', 10);
  expect(v1.decision === 'allow', 'allowlisted tool is allowed');
  const v2 = await guard(A_ALLOW, 'delete_rows', 'high', 'dd', 10);
  expect(v2.decision === 'block' && v2.escalation === true, 'unlisted tool -> block + escalation');
}

// 4. Tool risk must not exceed the agent's own risk.
{
  const v1 = await guard(A_RISK, 'get_user', 'low', 'ee', 10);
  expect(v1.decision === 'allow', 'tool at agent risk level is allowed');
  const v2 = await guard(A_RISK, 'delete_rows', 'critical', 'ff', 10);
  expect(v2.decision === 'block' && v2.escalation === true, 'critical tool on low-risk agent -> block + escalation');
}

// 5. Per-agent approval requirements: '*' forces approval without blocking.
{
  const v = await guard(A_APPROVE_ALL, 'get_user', 'low', 'gg', 10);
  expect(v.decision === 'allow' && v.force_approval === true, 'approval_required_for * forces approval');
}

// 6. Hourly call cap: the 3rd call in the hour is blocked (no risk event).
{
  await db.exec(`
    insert into public.agent_tool_calls (organization_id, agent_id, tool_name, arguments_hash, args_bytes, decision)
    values ('${ORG}', '${A_LIMIT}', 'get_user', 'h1', 10, 'allowed'),
           ('${ORG}', '${A_LIMIT}', 'get_user', 'h2', 10, 'allowed');
  `);
  const before = (await db.query(`select count(*)::int as n from public.risk_events where organization_id = '${ORG}'`)).rows[0].n;
  const v = await guard(A_LIMIT, 'get_user', 'low', 'h3', 10);
  expect(v.decision === 'block' && v.reasons[0].includes('call limit'), 'hourly call cap blocks');
  const after = (await db.query(`select count(*)::int as n from public.risk_events where organization_id = '${ORG}'`)).rows[0].n;
  expect(after === before, 'plain limit hit creates no risk event');
}

// 7. Hourly data-volume cap.
{
  await db.exec(`
    insert into public.agent_tool_calls (organization_id, agent_id, tool_name, arguments_hash, args_bytes, result_bytes, decision)
    values ('${ORG}', '${A_VOLUME}', 'get_user', 'v1', 60, 30, 'allowed');
  `);
  const v = await guard(A_VOLUME, 'get_user', 'low', 'v2', 20);
  expect(v.decision === 'block' && v.reasons[0].includes('volume'), 'hourly volume cap blocks');
  const v2 = await guard(A_VOLUME, 'get_user', 'low', 'v3', 5);
  expect(v2.decision === 'allow', 'volume under the cap is allowed');
}

// 8. Loop detection: 5 identical in a row -> the 6th is blocked + risk event;
//    a different call breaks the run.
{
  for (let i = 0; i < 5; i++) {
    await db.exec(`
      insert into public.agent_tool_calls (organization_id, agent_id, tool_name, arguments_hash, args_bytes, decision)
      values ('${ORG}', '${A_LOOP}', 'get_user', 'loop', 10, 'allowed');
    `);
  }
  const before = (await db.query(`select count(*)::int as n from public.risk_events where organization_id = '${ORG}'`)).rows[0].n;
  const v = await guard(A_LOOP, 'get_user', 'low', 'loop', 10);
  expect(v.decision === 'block' && v.reasons[0].includes('loop detected'), 'runaway loop is blocked');
  const after = (await db.query(`select count(*)::int as n from public.risk_events where organization_id = '${ORG}'`)).rows[0].n;
  expect(after === before + 1, 'loop creates a risk event');
  await db.exec(`
    insert into public.agent_tool_calls (organization_id, agent_id, tool_name, arguments_hash, args_bytes, decision)
    values ('${ORG}', '${A_LOOP}', 'list_files', 'other', 10, 'allowed');
  `);
  const v2 = await guard(A_LOOP, 'get_user', 'low', 'loop', 10);
  expect(v2.decision === 'allow', 'a different call breaks the loop run');
}

// 9. Unknown agent: fails closed with an exception.
{
  let threw = '';
  try {
    await db.query(`select public.check_agent_guardrails('${ORG}'::uuid, gen_random_uuid(), 'get_user', 'low', 'zz', 10)`);
  } catch (e) {
    threw = e.message;
  }
  expect(threw.includes('not found'), 'unknown agent raises (fail closed)');
}

// 10. RLS: members read their org's agent activity.
{
  const res = await db.query(`select count(*)::int as n from public.agent_tool_calls where organization_id = '${ORG}'::uuid`);
  expect(res.rows[0].n > 0, 'member can read agent_tool_calls');
}

if (failures > 0) {
  console.error(`\n${failures} assertion(s) FAILED`);
  process.exit(1);
}
console.log('\nAll agent guardrail checks passed.');
