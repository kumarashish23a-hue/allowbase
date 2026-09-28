// Verifies migration 020 (production hardening) against in-memory Postgres:
//   rate limiting, policy versioning + rollback, API key scopes / IP allow-lists /
//   rotation / emergency revoke, approval expiry / escalation / delegation /
//   comments, and the monitoring summary + alerts.
// Run: node scripts/verify-hardening.mjs
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';

let failures = 0;
function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) failures++;
}
async function expectError(sql, pattern, label) {
  try {
    await db.query(sql);
    expect(false, `${label} (no error raised)`);
  } catch (error) {
    const matched = pattern.test(error.message);
    if (!matched) console.log('     got:', error.message);
    expect(matched, label);
  }
}

const db = new PGlite();
await db.exec(`
  create schema if not exists auth;
  create schema if not exists extensions;
  create table if not exists auth.users (id uuid primary key, email text, raw_user_meta_data jsonb);
  create or replace function auth.uid() returns uuid language sql stable as $$ select null::uuid $$;
  do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon; end if;
    if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated; end if;
    if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role; end if;
  end $$;
  -- pgcrypto stand-ins (verification only; Supabase ships pgcrypto).
  create or replace function extensions.gen_random_bytes(n int) returns bytea language sql
    as $$ select decode(md5(random()::text) || md5(random()::text), 'hex') $$;
  create or replace function extensions.digest(data text, algo text) returns bytea language sql
    as $$ select sha256(convert_to(data, 'utf8')) $$;
`);

const dir = new URL('../supabase/migrations/', import.meta.url).pathname;
const FALLBACK_UUID = `
  create or replace function public.gen_random_uuid() returns uuid
  language sql as $$ select md5(random()::text || clock_timestamp()::text)::uuid $$;
`;
for (const file of readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) {
  const sql = readFileSync(join(dir, file), 'utf8').replace(
    'create extension if not exists "pgcrypto";',
    '-- pgcrypto stubbed',
  );
  try {
    await db.exec(FALLBACK_UUID + sql);
  } catch (error) {
    console.error(`FAIL applying ${file}: ${error.message}`);
    process.exit(1);
  }
}
console.log('ok   all migrations applied');

const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ADMIN = 'b0000000-0000-4000-8000-0000000000a2';
const VIEWER = 'b0000000-0000-4000-8000-0000000000b3';
const SECURITY = 'b0000000-0000-4000-8000-0000000000c4';

async function actAs(userId) {
  await db.exec(`create or replace function auth.uid() returns uuid language sql stable
    as $$ select ${userId ? `'${userId}'::uuid` : 'null::uuid'} $$;`);
}

await db.exec(`
  insert into auth.users (id, email) values
    ('${ADMIN}', 'admin@test.dev'), ('${VIEWER}', 'viewer@test.dev'), ('${SECURITY}', 'sec@test.dev')
  on conflict (id) do nothing;
  insert into public.organization_members (organization_id, user_id, role, status) values
    ('${ORG}', '${ADMIN}', 'admin', 'active'),
    ('${ORG}', '${VIEWER}', 'viewer', 'active'),
    ('${ORG}', '${SECURITY}', 'security', 'active')
  on conflict (organization_id, user_id) do update set role = excluded.role, status = 'active';
`);

// ------------------------------------------------------------------ 1. rate limiting
{
  const hit = async () =>
    (await db.query(`select public.check_rate_limit('test:bucket', 2, 60) as r`)).rows[0].r;
  const a = await hit();
  const b = await hit();
  const c = await hit();
  expect(a.allowed && a.remaining === 1, 'rate limit: first hit allowed, 1 remaining');
  expect(b.allowed && b.remaining === 0, 'rate limit: second hit allowed, 0 remaining');
  expect(c.allowed === false, 'rate limit: third hit rejected');
  const other = (await db.query(`select public.check_rate_limit('test:other', 2, 60) as r`)).rows[0].r;
  expect(other.allowed, 'rate limit: buckets are independent');
  await expectError(`select public.check_rate_limit('', 2, 60)`, /bucket/, 'rate limit: empty bucket rejected');
}

// ------------------------------------------------------------------ 2. policy versioning
{
  await actAs(ADMIN);
  const created = await db.query(
    `insert into public.policies (organization_id, name, action, rule, priority)
     values ('${ORG}', 'Versioned', 'block', '{"conditions":[{"field":"ai.is_external","operator":"equals","value":true}]}', 50)
     returning id, version`,
  );
  const pid = created.rows[0].id;
  expect(created.rows[0].version === 1, 'versioning: new policy starts at version 1');

  await db.query(`update public.policies set rule = '{"conditions":[]}'::jsonb, action = 'mask' where id = '${pid}'`);
  await db.query(`update public.policies set status = 'paused' where id = '${pid}'`);
  await db.query(`update public.policies set status = 'paused' where id = '${pid}'`); // no-op
  const versions = (
    await db.query(`select version, change_type, action from public.policy_versions where policy_id = '${pid}' order by version`)
  ).rows;
  expect(versions.length === 3, 'versioning: 3 snapshots (create, update, status); no-op skipped');
  expect(versions[1].change_type === 'updated' && versions[1].action === 'mask', 'versioning: v2 is an update');
  expect(versions[2].change_type === 'status_changed', 'versioning: v3 is a status change');

  const rb = (await db.query(`select public.rollback_policy('${pid}', 1) as r`)).rows[0].r;
  const afterRb = (await db.query(`select action, status, version from public.policies where id = '${pid}'`)).rows[0];
  expect(rb.new_version === 4 && afterRb.action === 'block' && afterRb.status === 'active', 'rollback: restores v1 as v4');
  const rbRow = (
    await db.query(`select change_type, rolled_back_from from public.policy_versions where policy_id = '${pid}' and version = 4`)
  ).rows[0];
  expect(rbRow.change_type === 'rolled_back' && rbRow.rolled_back_from === 1, 'rollback: recorded as rolled_back from v1');

  await db.query(`delete from public.policies where id = '${pid}'`);
  const del = (await db.query(`select change_type from public.policy_versions where policy_id = '${pid}' and version = 5`)).rows[0];
  expect(del?.change_type === 'deleted', 'versioning: deletion snapshot kept');
  const restored = (await db.query(`select public.rollback_policy('${pid}', 2) as r`)).rows[0].r;
  const exists = (await db.query(`select action from public.policies where id = '${pid}'`)).rows[0];
  expect(restored.recreated === true && exists?.action === 'mask', 'rollback: deleted policy recreated from v2');
  await expectError(`select public.rollback_policy('${pid}', 5)`, /deletion/, 'rollback: cannot restore a deletion');

  const audit = (await db.query(`select count(*)::int n from public.audit_logs where action = 'policy_rolled_back' and resource_id = '${pid}'`)).rows[0].n;
  expect(audit === 2, 'rollback: audited');

  await actAs(VIEWER);
  await expectError(`select public.rollback_policy('${pid}', 1)`, /owner, admin, or security/, 'rollback: viewer denied');

  await actAs(ADMIN);
  await db.exec(`set role authenticated`);
  let directWriteBlocked = false;
  try {
    await db.query(
      `insert into public.policy_versions (policy_id, organization_id, version, change_type, name, status, priority, rule, action)
       values ('${pid}', '${ORG}', 99, 'updated', 'x', 'active', 1, '{}', 'allow')`,
    );
  } catch {
    directWriteBlocked = true;
  }
  await db.exec(`reset role`);
  expect(directWriteBlocked, 'versioning: clients cannot write policy_versions');
}

// ------------------------------------------------------------------ 3. API key security
{
  await actAs(ADMIN);
  const created = (
    await db.query(
      `select public.create_api_key('${ORG}', 'Restricted', array['ingest'], null, array['10.0.0.0/8']::cidr[], 5) as r`,
    )
  ).rows[0].r;
  expect(created.key.startsWith('dcp_live_'), 'api keys: minted with dcp_live_ prefix');
  const hash = createHash('sha256').update(created.key).digest('hex');

  await actAs(null);
  const auth = async (ip, scopes) =>
    (await db.query(`select public.authorize_api_key($1, $2, $3) as r`, [hash, ip, scopes])).rows[0].r;

  const ok = await auth('10.1.2.3', ['ingest']);
  expect(ok.ok === true && ok.rate_limit_per_minute === 5, 'api keys: allowed IP + scope authorizes');
  const badIp = await auth('192.168.1.1', ['ingest']);
  expect(badIp.ok === false && badIp.reason === 'ip', 'api keys: IP outside allow-list denied');
  const noIp = await auth(null, ['ingest']);
  expect(noIp.ok === false && noIp.reason === 'ip', 'api keys: missing IP denied when list set');
  const badScope = await auth('10.1.2.3', ['ingest', 'ingest:content']);
  expect(badScope.ok === false && badScope.reason === 'scope', 'api keys: missing ingest:content scope denied');
  const garbage = (await db.query(`select public.authorize_api_key('nothex', '1.1.1.1', array['ingest']) as r`)).rows[0].r;
  expect(garbage.ok === false && garbage.reason === 'invalid', 'api keys: malformed hash rejected');

  const usage = (await db.query(`select use_count, host(last_used_ip) ip from public.api_keys where id = '${created.id}'`)).rows[0];
  expect(Number(usage.use_count) === 1 && usage.ip === '10.1.2.3', 'api keys: usage + last IP tracked');
  const denials = (await db.query(`select count(*)::int n from public.audit_logs where resource_id = '${created.id}' and result = 'denied'`)).rows[0].n;
  expect(denials === 3, 'api keys: denials audited');

  await actAs(ADMIN);
  await expectError(
    `select public.create_api_key('${ORG}', 'Bad', array['admin'])`,
    /scopes/,
    'api keys: unknown scope rejected',
  );
  await expectError(
    `select public.create_api_key('${ORG}', 'Bad', array['ingest'], null, '{}', 0)`,
    /rate limit/,
    'api keys: invalid rate limit rejected',
  );

  const rotated = (await db.query(`select public.rotate_api_key('${created.id}', 12) as r`)).rows[0].r;
  const oldKey = (await db.query(`select expires_at, revoked_at from public.api_keys where id = '${created.id}'`)).rows[0];
  const newKey = (await db.query(`select rotated_from, rate_limit_per_minute, allowed_cidrs::text[] cidrs from public.api_keys where id = '${rotated.id}'`)).rows[0];
  expect(rotated.key !== created.key && newKey.rotated_from === created.id, 'rotation: new key linked to old');
  expect(newKey.rate_limit_per_minute === 5 && newKey.cidrs[0] === '10.0.0.0/8', 'rotation: settings carried over');
  const hoursLeft = (new Date(oldKey.expires_at).getTime() - Date.now()) / 3600000;
  expect(oldKey.revoked_at === null && hoursLeft > 11 && hoursLeft <= 12.01, 'rotation: old key valid for grace period');

  await db.query(`select public.update_api_key_settings('${rotated.id}', array['ingest','ingest:content'], '{}', 60)`);
  const updated = (await db.query(`select scopes, rate_limit_per_minute from public.api_keys where id = '${rotated.id}'`)).rows[0];
  expect(updated.scopes.includes('ingest:content') && updated.rate_limit_per_minute === 60, 'api keys: settings updated');

  await actAs(VIEWER);
  await expectError(`select public.rotate_api_key('${rotated.id}')`, /owner or admin/, 'rotation: viewer denied');
  await expectError(`select public.revoke_all_api_keys('${ORG}', 'x')`, /owner or admin/, 'emergency revoke: viewer denied');

  await actAs(ADMIN);
  await expectError(`select public.revoke_all_api_keys('${ORG}', '  ')`, /reason/, 'emergency revoke: reason required');
  const all = (await db.query(`select public.revoke_all_api_keys('${ORG}', 'suspected leak') as r`)).rows[0].r;
  const live = (await db.query(`select count(*)::int n from public.api_keys where organization_id = '${ORG}' and revoked_at is null`)).rows[0].n;
  expect(all.revoked_count >= 2 && live === 0, 'emergency revoke: every live key revoked');
  await actAs(null);
  const afterRevoke = await auth('10.1.2.3', ['ingest']);
  expect(afterRevoke.ok === false && afterRevoke.reason === 'invalid', 'emergency revoke: revoked key no longer authorizes');
}

// ------------------------------------------------------------------ 4. approval workflow
{
  await actAs(null);
  const mkApproval = async (createdAgo, expiresIn) => {
    const req = (
      await db.query(
        `insert into public.ai_requests (organization_id, purpose, status) values ('${ORG}', 'Approval test', 'review') returning id`,
      )
    ).rows[0].id;
    return (
      await db.query(
        `insert into public.approval_requests (organization_id, ai_request_id, requested_by, created_at, expires_at)
         values ('${ORG}', '${req}', '${VIEWER}', now() - interval '${createdAgo}', now() + interval '${expiresIn}')
         returning id, ai_request_id`,
      )
    ).rows[0];
  };

  const fresh = await mkApproval('1 minute', '72 hours');
  const stale = await mkApproval('30 hours', '42 hours');
  const expired = await mkApproval('80 hours', '-8 hours');

  await actAs(VIEWER);
  const sweep = (await db.query(`select public.expire_stale_approvals('${ORG}') as r`)).rows[0].r;
  expect(sweep.expired === 1 && sweep.escalated >= 1, 'approvals: sweep expires 1 and auto-escalates stale');
  const expiredRow = (await db.query(`select a.status, r.status rs from public.approval_requests a join public.ai_requests r on r.id = a.ai_request_id where a.id = '${expired.id}'`)).rows[0];
  expect(expiredRow.status === 'expired' && expiredRow.rs === 'blocked', 'approvals: expired request is blocked (fail closed)');
  const staleRow = (await db.query(`select escalation_level from public.approval_requests where id = '${stale.id}'`)).rows[0];
  expect(staleRow.escalation_level === 1, 'approvals: stale approval escalated to level 1');

  const esc = (await db.query(`select public.escalate_approval('${fresh.id}', 'customer waiting') as r`)).rows[0].r;
  expect(esc.escalation_level === 1, 'approvals: member can escalate manually');

  await expectError(`select public.delegate_approval('${fresh.id}', '${SECURITY}')`, /owner or admin/, 'delegation: viewer cannot delegate');
  await actAs(ADMIN);
  await expectError(`select public.delegate_approval('${fresh.id}', '${VIEWER}')`, /assignee must be/, 'delegation: viewer cannot be assignee');
  await db.query(`select public.delegate_approval('${fresh.id}', '${SECURITY}')`);

  await actAs(SECURITY);
  await expectError(`select public.decide_approval('${stale.id}', 'approved')`, /delegated reviewer/, 'delegation: security cannot decide unassigned');
  await db.query(`select public.add_approval_comment('${fresh.id}', 'Checked the ticket, looks legitimate.')`);
  await expectError(`select public.add_approval_comment('${fresh.id}', '   ')`, /1-2000/, 'comments: empty comment rejected');
  const decided = (await db.query(`select public.decide_approval('${fresh.id}', 'approved', 'ok') as r`)).rows[0].r;
  expect(decided.request_status === 'allowed', 'delegation: assigned security reviewer can decide');

  await actAs(ADMIN);
  await expectError(`select public.decide_approval('${expired.id}', 'approved')`, /no longer pending/, 'approvals: expired cannot be decided');

  const timeline = (await db.query(`select public.get_approval_timeline('${fresh.id}') as t`)).rows[0].t;
  const kinds = timeline.map((t) => t.kind === 'comment' ? 'comment' : t.action);
  expect(
    kinds.includes('approval_escalated') && kinds.includes('approval_delegated') && kinds.includes('comment') && kinds.includes('approval_approved'),
    'timeline: escalation, delegation, comment, decision present',
  );
  const decisionEvent = timeline.find((t) => t.action === 'approval_approved');
  expect(decisionEvent?.metadata?.via_delegation === true, 'timeline: decision marked via delegation');
}

// ------------------------------------------------------------------ 5. monitoring
{
  await actAs(null);
  await db.exec(`
    insert into public.request_metrics (organization_id, source, provider, model, outcome, status_code, latency_ms, provider_latency_ms, input_tokens, output_tokens, cost_usd)
    select '${ORG}', 'gateway', 'openai', 'gpt-4o-mini',
      case when g % 5 = 0 then 'error' else 'allowed' end,
      case when g % 5 = 0 then 502 else 200 end,
      100 + g * 10, 80 + g * 10, 100, 50, 0.0001
    from generate_series(1, 30) g;
  `);
  await actAs(VIEWER);
  const summary = (await db.query(`select public.get_monitoring_summary('${ORG}', 24) as s`)).rows[0].s;
  expect(Number(summary.totals.requests) === 30 && Number(summary.totals.errors) === 6, 'monitoring: totals counted');
  expect(summary.latency.p95 > summary.latency.p50, 'monitoring: latency percentiles computed');
  expect(Number(summary.totals.cost_usd) > 0, 'monitoring: cost summed');
  expect(summary.alerts.some((a) => a.code === 'error_rate' && a.severity === 'critical'), 'monitoring: error-rate alert raised at 20%');
  expect(summary.providers[0].provider === 'openai', 'monitoring: provider breakdown');

  const OTHER = 'b0000000-0000-4000-8000-0000000000ff';
  await actAs(OTHER);
  await expectError(`select public.get_monitoring_summary('${ORG}', 24)`, /organization member/, 'monitoring: non-member denied');
}

if (failures > 0) {
  console.error(`\n${failures} hardening check(s) failed.`);
  process.exit(1);
}
console.log('\nHardening verification passed.');
