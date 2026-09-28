// Verifies the 020_rate_limits.sql fixed-window rate limiter against
// in-memory Postgres (PGlite).
// Run: node scripts/verify-rate-limit.mjs
import { readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';

const file = new URL('../supabase/migrations/020_rate_limits.sql', import.meta.url).pathname;
const sql = readFileSync(file, 'utf8');

const db = new PGlite();

// Minimal stand-in for Supabase Auth (same pattern as verify-sql.mjs).
await db.exec(`
  create schema if not exists auth;
  create table if not exists auth.users (
    id uuid primary key,
    email text,
    raw_user_meta_data jsonb
  );
`);

// Supabase-provided roles (grants in the migration target them).
await db.exec(`
  do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon; end if;
    if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated; end if;
    if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role; end if;
  end $$;
`);

await db.exec(sql);
console.log('ok   migration 020_rate_limits.sql applied');

let failed = false;
function assert(label, condition, detail = '') {
  if (condition) {
    console.log(`ok   ${label}${detail ? ' — ' + detail : ''}`);
  } else {
    failed = true;
    console.error(`FAIL ${label}${detail ? ' — ' + detail : ''}`);
  }
}

async function check(bucket, max, windowSecs) {
  const r = await db.query(`select public.check_rate_limit($1, $2, $3) as d`, [bucket, max, windowSecs]);
  return r.rows[0].d;
}

// (a) First call on a fresh bucket is allowed.
let d = await check('rl:test:bucket-a', 3, 60);
assert('first call allowed', d.allowed === true, JSON.stringify(d));
assert('first call shape', d.retry_after_seconds === 0 && d.limit === 3 && d.count === 1, JSON.stringify(d));

// (b) After max calls, further calls are denied with retry_after_seconds > 0.
await check('rl:test:bucket-a', 3, 60); // count 2
await check('rl:test:bucket-a', 3, 60); // count 3 (at limit)
d = await check('rl:test:bucket-a', 3, 60); // count 4 -> denied
assert('over-limit denied', d.allowed === false, JSON.stringify(d));
assert('retry_after_seconds > 0', d.retry_after_seconds > 0, `got ${d.retry_after_seconds}`);
assert('count keeps incrementing', d.count === 4 && d.limit === 3, JSON.stringify(d));

// (c) A different bucket_key is unaffected by (b)'s exhaustion.
d = await check('rl:test:bucket-b', 3, 60);
assert('other bucket unaffected', d.allowed === true && d.count === 1, JSON.stringify(d));

// (d) Backdate window_start past the window: next call starts a fresh window.
await db.exec(`
  update public.rate_limit_counters
  set window_start = now() - interval '61 seconds', count = 999
  where bucket_key = 'rl:test:bucket-a'
`);
d = await check('rl:test:bucket-a', 3, 60);
assert('window reset allows again', d.allowed === true && d.count === 1 && d.retry_after_seconds === 0, JSON.stringify(d));

// Seed rules exist with the expected defaults.
const rules = await db.query(`select endpoint, max_requests, window_seconds from public.rate_limit_rules order by endpoint`);
const expected = {
  'ai-gateway': [120, 60],
  'evaluate-ai-request': [300, 60],
  'ingest-event': [600, 60],
};
assert('three seed rules', rules.rows.length === 3, `got ${rules.rows.length}`);
for (const row of rules.rows) {
  const exp = expected[row.endpoint];
  assert(`seed rule ${row.endpoint}`, exp && row.max_requests === exp[0] && row.window_seconds === exp[1], JSON.stringify(row));
}

// RLS is enabled with no permissive policies (deny-by-default).
const rls = await db.query(`
  select tablename, rowsecurity from pg_tables
  where schemaname = 'public' and tablename in ('rate_limit_counters', 'rate_limit_rules')
`);
assert('rls enabled on both tables', rls.rows.length === 2 && rls.rows.every((r) => r.rowsecurity === true), JSON.stringify(rls.rows));
const pols = await db.query(`
  select count(*)::int as n from pg_policies
  where schemaname = 'public' and tablename in ('rate_limit_counters', 'rate_limit_rules')
`);
assert('no permissive policies', pols.rows[0].n === 0, `got ${pols.rows[0].n}`);

// EXECUTE is granted to anon, authenticated, service_role (Postgres also
// grants to PUBLIC by default on new functions, so check inclusion).
const grants = await db.query(`
  select grantee from information_schema.routine_privileges
  where routine_schema = 'public' and routine_name = 'check_rate_limit'
    and privilege_type = 'EXECUTE'
`);
const grantees = new Set(grants.rows.map((r) => r.grantee));
assert('execute grants', ['anon', 'authenticated', 'service_role'].every((r) => grantees.has(r)), [...grantees].join(','));

if (failed) process.exit(1);
console.log('all rate-limit assertions passed');
