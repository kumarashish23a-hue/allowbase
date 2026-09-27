// Verifies the policy builder produces rules the REAL enforcement engine
// (policy_condition_matches from supabase/migrations/012_content_detection.sql)
// understands. Uses PGlite with stub tables + the exact function body.
// Run: node scripts/verify-policy-builder.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { PGlite } from '@electric-sql/pglite';

const require = createRequire(import.meta.url);
const ts = require('typescript');

let failures = 0;
function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) failures++;
}

// --- 1. Load the REAL encodeValue from the service (transpiled, like verify-detect) ---
const src = readFileSync(new URL('../src/services/policyService.ts', import.meta.url), 'utf8');
// Stub the runtime imports: policyService imports ../lib/supabase and ../lib/db (types).
// Replace them with a stub module so we can import encodeValue standalone.
const stubbed = src
  .replace(/from '\.\.\/lib\/supabase'/g, `from './stub-supabase.mjs'`)
  .replace(/from '\.\.\/lib\/db'/g, `from './stub-supabase.mjs'`)
  .replace(/from '\.\.\/types'/g, `from './stub-supabase.mjs'`);
const stubPath = join(tmpdir(), 'stub-supabase.mjs');
writeFileSync(stubPath, 'export const getActiveOrganizationId = async () => null; export const getSupabase = () => null;');
const js = ts.transpileModule(stubbed, { compilerOptions: { module: ts.ModuleKind.ESNext } }).outputText;
const tmpFile = join(tmpdir(), `policyservice-test-${Date.now()}.mjs`);
// Fix relative stub import to absolute file URL
const jsFixed = js.replace(/'.\/stub-supabase.mjs'/g, `'${pathToFileURL(stubPath).href}'`);
writeFileSync(tmpFile, jsFixed);
const { encodeValue } = await import(pathToFileURL(tmpFile).href);

// --- 2. PGlite with stub tables + the REAL function body from migration 012 ---
const db = new PGlite();
await db.exec(`
  create table public.data_assets (
    id uuid primary key,
    organization_id uuid not null,
    classification text not null,
    sensitivity_level text not null
  );
  create table public.ai_models (
    id uuid primary key,
    is_external boolean not null,
    is_approved boolean not null
  );
`);
const migration = readFileSync(new URL('../supabase/migrations/012_content_detection.sql', import.meta.url), 'utf8');
const start = migration.indexOf('create or replace function public.policy_condition_matches(');
const endMarker = '\n$$;';
const end = migration.indexOf(endMarker, start);
if (start === -1 || end === -1) throw new Error('Could not extract policy_condition_matches from migration 012');
await db.exec(migration.slice(start, end + endMarker.length));

const ORG = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ASSET = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const MODEL = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
await db.exec(`
  insert into public.data_assets (id, organization_id, classification, sensitivity_level)
  values ('${ASSET}', '${ORG}', 'confidential', 'high');
  insert into public.ai_models (id, is_external, is_approved)
  values ('${MODEL}', true, false);
`);

async function matches(field, operator, draftValue, findings = []) {
  const encoded = encodeValue(field, operator, draftValue);
  const res = await db.query(
    `select public.policy_condition_matches($1, $2, $3::jsonb, $4::uuid, $5::uuid[], (select m from public.ai_models m where m.id = $6::uuid), $7, $8::jsonb) as matched`,
    [field, operator, JSON.stringify(encoded), ORG, [ASSET], MODEL, 'Customer Analysis', JSON.stringify(findings)],
  );
  return res.rows[0].matched;
}

// --- 3. Cases: the builder's output must drive the engine correctly ---
expect(await matches('data.classification', 'in', ['confidential', 'restricted']) === true,
  'data.classification in [confidential, restricted] matches confidential asset');
expect(await matches('data.classification', 'in', ['public']) === false,
  'data.classification in [public] does not match');
expect(await matches('data.classification', 'equals', 'confidential') === true,
  'data.classification equals confidential matches');
expect(await matches('data.sensitivity_level', 'in', ['high', 'critical']) === true,
  'data.sensitivity_level in [high, critical] matches');
expect(await matches('ai.is_external', 'equals', true) === true,
  'ai.is_external is true matches external model');
expect(await matches('ai.is_external', 'equals', false) === false,
  'ai.is_external is false does not match external model');
expect(await matches('ai.is_approved', 'not_equals', true) === true,
  'ai.is_approved is not true matches unapproved model');
expect(await matches('content.category', 'in', ['email', 'phone'], [{ category: 'email', count: 2 }]) === true,
  'content.category in [email, phone] matches email finding');
expect(await matches('content.category', 'in', ['phone'], [{ category: 'email', count: 2 }]) === false,
  'content.category in [phone] does not match email finding');
expect(await matches('purpose', 'equals', 'customer analysis') === true,
  'purpose is "customer analysis" matches case-insensitively');
expect(await matches('purpose', 'in', 'Support, Customer Analysis') === true,
  'purpose is one of "Support, Customer Analysis" matches');
// The old demo builder's vocabulary must NOT match (fail closed) — this is the
// trap the new builder removes.
expect(await matches('Data', '=', 'PII') === false,
  'OLD demo field "Data" with operator "=" never matches (fail closed)');

console.log(failures === 0 ? '\nAll policy-builder checks passed.' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
