// Verifies migration 012 (deterministic content detection) end to end:
//   A. Unit tests for supabase/functions/_shared/detect.ts (transpiled with
//      the project's TypeScript, run in Node — same pattern as verify-classify).
//   B. PGlite test: 001-012 apply, content.category policy conditions drive
//      block/allow decisions, findings are stored, critical findings raise risk.
// Run: node scripts/verify-detect.mjs
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

// ---------------------------------------------------------------- A. detectors
const require = createRequire(join(process.cwd(), 'package.json'));
const ts = require('typescript');
const src = readFileSync('supabase/functions/_shared/detect.ts', 'utf8');
const { outputText, diagnostics } = ts.transpileModule(src, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
  reportDiagnostics: true,
});
const fatal = (diagnostics ?? []).filter((d) => d.category === ts.DiagnosticCategory.Error);
if (fatal.length > 0) {
  console.error('TypeScript errors in detect.ts:');
  for (const d of fatal) console.error(' -', ts.flattenDiagnosticMessageText(d.messageText, ' '));
  process.exit(1);
}
const dir = join(tmpdir(), 'dataplane-detect-test');
mkdirSync(dir, { recursive: true });
const compiled = join(dir, 'detect.mjs');
writeFileSync(compiled, outputText);
const D = await import(pathToFileURL(compiled).href);

const cats = (f) => f.map((x) => x.category).sort().join(',');

expect(D.detectSensitiveContent('').length === 0, 'empty string -> no findings');
expect(D.detectSensitiveContent('Hello world, a normal support ticket about login issues.').length === 0, 'clean text -> no findings');

let f = D.detectSensitiveContent('Contact me at jane.doe@example.com for details.');
expect(f.length === 1 && f[0].category === 'email' && f[0].severity === 'medium', 'email detected');
expect(!JSON.stringify(f).includes('jane.doe@example.com'), 'findings never contain raw matched values');
expect(f[0].detector === D.DETECTOR_VERSION, 'detector version stamped');

f = D.detectSensitiveContent('Call +1 415-555-0132 tomorrow.');
expect(f.length === 1 && f[0].category === 'phone', 'phone detected');
expect(D.detectSensitiveContent('call 123').length === 0, 'short digit run is not a phone');

f = D.detectSensitiveContent('card 4111 1111 1111 1111 expires 12/28');
expect(f.length === 1 && f[0].category === 'credit_card' && f[0].severity === 'high' && f[0].confidence >= 0.95, 'valid card (Luhn) detected');
expect(D.detectSensitiveContent('card 4111 1111 1111 1112').every((x) => x.category !== 'credit_card'), 'Luhn-invalid number rejected');

f = D.detectSensitiveContent('SSN 123-45-6789 on file');
expect(f.some((x) => x.category === 'gov_id' && x.severity === 'high'), 'SSN detected');

f = D.detectSensitiveContent('key AKIAIOSFODNN7EXAMPLE in config');
expect(f.some((x) => x.category === 'api_key' && x.severity === 'critical'), 'AWS access key detected');

f = D.detectSensitiveContent('-----BEGIN RSA PRIVATE KEY-----\nMIIE...');
expect(f.some((x) => x.category === 'private_key' && x.severity === 'critical'), 'private key detected');

const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
f = D.detectSensitiveContent('token ' + jwt + ' leaked');
expect(f.some((x) => x.category === 'jwt' && x.severity === 'high'), 'JWT detected');

f = D.detectSensitiveContent('db_password = "s3cr3t-pass!" # rotate me');
expect(f.some((x) => x.category === 'secret' && x.severity === 'critical'), 'generic secret assignment detected');

f = D.detectSensitiveContent('token ghp_abcdefghijklmnopqrstuvwxyz1234567890 is live');
expect(f.some((x) => x.category === 'api_key' && x.severity === 'critical'), 'github token detected');

f = D.detectSensitiveContent('charge with sk_live_abcdef1234567890 now');
expect(f.some((x) => x.category === 'api_key' && x.severity === 'critical'), 'stripe key detected');

expect(D.detectSensitiveContent('see the logo at file@host.png').length === 0, 'file-like email rejected by TLD guard');

f = D.detectSensitiveContent('Email jane@example.com, phone 415-555-0132, key AKIAIOSFODNN7EXAMPLE');
expect(cats(f) === 'api_key,email,phone', 'multiple categories in one scan');

f = D.detectSensitiveContent('AKIAIOSFODNN7EXAMPLE and AKIAI44QH8DHBEXAMPLE keys');
const ak = f.find((x) => x.category === 'api_key');
expect(ak && ak.count === 2, 'match counts aggregated per category');

f = D.detectSensitiveContent(Array(150).fill('a@b.com').join(' '));
expect(f.find((x) => x.category === 'email').count === D.MAX_FINDINGS_PER_CATEGORY, 'per-category count capped');

expect(D.hasCriticalFinding(D.detectSensitiveContent('AKIAIOSFODNN7EXAMPLE')), 'hasCriticalFinding true for secrets');
expect(!D.hasCriticalFinding(D.detectSensitiveContent('jane@example.com')), 'hasCriticalFinding false for email only');
expect(D.findingCategories(D.detectSensitiveContent('a@b.com 415-555-0132')).sort().join(',') === 'email,phone', 'findingCategories distinct');

// ---------------------------------------------------------------- B. SQL path
const migDir = new URL('../supabase/migrations/', import.meta.url).pathname;
const files = readdirSync(migDir).filter((f2) => f2.endsWith('.sql')).sort();

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
console.log('ok    all migrations (001-012) apply');

const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaa001';
const ADMIN = 'b1111111-1111-4111-8111-111111111111';
const MODEL = 'f2222222-2222-4222-8222-222222222222';

await db.exec(`
  insert into auth.users (id, email) values ('${ADMIN}', 'admin@test.local');
  create or replace function auth.uid() returns uuid language sql stable as $$ select '${ADMIN}'::uuid $$;
  insert into public.organizations (id, name, slug) values ('${ORG}', 'Test Org', 'test-org');
  insert into public.organization_members (organization_id, user_id, role, status)
  values ('${ORG}', '${ADMIN}', 'admin', 'active');
  insert into public.ai_models (id, organization_id, name, provider, model_identifier, is_external, is_approved)
  values ('${MODEL}', '${ORG}', 'support-copilot', 'test', 'support-copilot', true, true);
  insert into public.policies (organization_id, name, description, status, priority, action, rule)
  values ('${ORG}', 'Block Secrets in AI Content', 'Secrets in content are blocked outright.',
          'active', 5, 'block',
          '{"conditions": [{"field": "content.category", "operator": "in", "value": ["secret", "private_key", "api_key"]}]}'::jsonb);
`);

async function evaluate(findings) {
  const r = await db.query(
    `select public.evaluate_ai_request(
       '${ORG}'::uuid, '${MODEL}'::uuid, 'test', '{}'::uuid[],
       '${ADMIN}'::uuid, null, 'chat', $1::jsonb) as v`,
    [JSON.stringify(findings)],
  );
  return r.rows[0].v;
}

const secretFindings = [
  { detector: 'regex-v1', category: 'api_key', severity: 'critical', confidence: 1, count: 1 },
];
let res = await evaluate(secretFindings);
expect(res.decision === 'block', 'secret in content -> block');
expect(res.risk === 'high', 'critical finding raises risk to high');
expect(Array.isArray(res.detections) && res.detections.length === 1, 'detections returned in response');

const stored = await db.query(
  `select detection_findings, status from public.ai_requests where id = $1::uuid`,
  [res.request_id],
);
expect(stored.rows[0].status === 'blocked', 'blocked request persisted');
expect(stored.rows[0].detection_findings.length === 1, 'findings stored on ai_requests');
expect(!JSON.stringify(stored.rows[0].detection_findings).includes('AKIA'), 'stored findings contain no raw secrets');

const emailFindings = [
  { detector: 'regex-v1', category: 'email', severity: 'medium', confidence: 0.9, count: 2 },
];
res = await evaluate(emailFindings);
expect(res.decision === 'allow', 'email-only content -> allow (no policy matches)');
expect(res.risk === 'low', 'non-critical findings keep low risk');

res = await evaluate([]);
expect(res.decision === 'allow', 'no content -> allow, backward compatible');

// Old 7-arg positional call still resolves via the defaulted 8th parameter.
const legacy = await db.query(
  `select public.evaluate_ai_request('${ORG}'::uuid, '${MODEL}'::uuid, 'legacy', '{}'::uuid[],
     '${ADMIN}'::uuid, null, 'chat') as v`,
);
expect(legacy.rows[0].v.decision === 'allow', '7-arg positional call still works (defaulted param)');

// not_in operator: finding present but outside the list -> matches.
await db.exec(`
  insert into public.policies (organization_id, name, status, priority, action, rule)
  values ('${ORG}', 'Block non-email content', 'active', 6, 'block',
          '{"conditions": [{"field": "content.category", "operator": "not_in", "value": ["email"]}]}'::jsonb);
`);
res = await evaluate(secretFindings);
expect(res.decision === 'block', 'not_in matches when finding category is outside the list');
res = await evaluate(emailFindings);
expect(res.decision === 'allow', 'not_in does not match when category is in the list');

// ingest_api_event threads findings through (real key, then idempotent replay).
const created = await db.query(
  `select public.create_api_key('${ORG}'::uuid, 'detect-test', array['ingest'], null) as k`,
);
const plaintext = created.rows[0].k.key;
const hashRow = await db.query(`select key_hash from public.api_keys where organization_id = '${ORG}'::uuid`);
const keyHash = hashRow.rows[0].key_hash;
expect(typeof plaintext === 'string' && plaintext.startsWith('dcp_live_'), 'test API key minted');

const first = await db.query(
  `select public.ingest_api_event($1, 'evt_detect_1', '${MODEL}'::uuid, null, 'test',
     '{}'::uuid[], null, 'chat', $2::jsonb) as v`,
  [keyHash, JSON.stringify(secretFindings)],
);
expect(first.rows[0].v.decision === 'block', 'ingest with secret content -> block');
expect(first.rows[0].v.idempotent_replay === false, 'first ingest is not a replay');

const replay = await db.query(
  `select public.ingest_api_event($1, 'evt_detect_1', '${MODEL}'::uuid, null, 'test',
     '{}'::uuid[], null, 'chat', $2::jsonb) as v`,
  [keyHash, JSON.stringify(secretFindings)],
);
expect(replay.rows[0].v.idempotent_replay === true, 'same event_id replays without re-evaluation');
expect(replay.rows[0].v.decision === 'block', 'replay returns the original verdict');
expect(Array.isArray(replay.rows[0].v.detections) && replay.rows[0].v.detections.length === 1, 'replay includes stored detections');

if (failures > 0) {
  console.error(`${failures} assertion(s) failed`);
  process.exit(1);
}
console.log('ok    all detection assertions passed');
