// Unit tests for the deterministic classification engine
// (supabase/functions/_shared/classify.ts).
// Compiles the shared module with the project's TypeScript and runs assertions
// in Node. No database needed.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const require = createRequire(join(process.cwd(), 'package.json'));
const ts = require('typescript');

const src = readFileSync('supabase/functions/_shared/classify.ts', 'utf8');
const { outputText, diagnostics } = ts.transpileModule(src, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
  reportDiagnostics: true,
});
const fatal = (diagnostics ?? []).filter((d) => d.category === ts.DiagnosticCategory.Error);
if (fatal.length > 0) {
  console.error('TypeScript errors in classify.ts:');
  for (const d of fatal) console.error(' -', ts.flattenDiagnosticMessageText(d.messageText, ' '));
  process.exit(1);
}
const dir = join(tmpdir(), 'dataplane-classify-test');
mkdirSync(dir, { recursive: true });
const compiled = join(dir, 'classify.mjs');
writeFileSync(compiled, outputText);
const C = await import(pathToFileURL(compiled).href);

let passed = 0;
let failed = 0;
function check(name, actual, expected) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    passed += 1;
  } else {
    failed += 1;
    console.error(`FAIL ${name}\n  expected ${e}\n  actual   ${a}`);
  }
}
const verdict = (name) => {
  const v = C.classifyColumn(name);
  return v ? { c: v.classification, s: v.sensitivity, cat: v.category, rev: v.needs_review } : null;
};

// --- normalization ---
check('normalize camelCase', C.normalizeColumnName('userEmail'), 'user_email');
check('normalize dashes', C.normalizeColumnName('EMAIL-ADDRESS'), 'email_address');
check('normalize quotes', C.normalizeColumnName('"e-mail"'), 'e_mail');

// --- PII ---
check('email', verdict('email'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('userEmail camelCase', verdict('userEmail'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('EMAIL_ADDRESS', verdict('EMAIL_ADDRESS'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('ssn', verdict('ssn'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('date_of_birth', verdict('date_of_birth'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('dob', verdict('dob'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('first_name', verdict('first_name'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('phone', verdict('phone'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('telephone', verdict('telephone'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('zip', verdict('zip'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });
check('ip_address', verdict('ip_address'), { c: 'confidential', s: 'high', cat: 'pii', rev: false });

// --- financial ---
check('card_number', verdict('card_number'), { c: 'restricted', s: 'critical', cat: 'financial', rev: false });
check('card_token is financial not credential', verdict('card_token'), { c: 'restricted', s: 'critical', cat: 'financial', rev: false });
check('cvv', verdict('cvv'), { c: 'restricted', s: 'critical', cat: 'financial', rev: false });
check('iban', verdict('iban'), { c: 'restricted', s: 'critical', cat: 'financial', rev: false });
check('salary high confidence', verdict('salary'), { c: 'confidential', s: 'high', cat: 'financial', rev: false });
check('amount needs review', verdict('amount'), { c: 'confidential', s: 'high', cat: 'financial', rev: true });

// --- credentials ---
check('password', verdict('password'), { c: 'restricted', s: 'critical', cat: 'credential', rev: false });
check('password_hash', verdict('password_hash'), { c: 'restricted', s: 'critical', cat: 'credential', rev: false });
check('api_key', verdict('api_key'), { c: 'restricted', s: 'critical', cat: 'credential', rev: false });
check('token alone is credential', verdict('token'), { c: 'restricted', s: 'critical', cat: 'credential', rev: false });

// --- healthcare ---
check('diagnosis', verdict('diagnosis'), { c: 'restricted', s: 'high', cat: 'healthcare', rev: false });

// --- identifiers / technical ---
check('customer_id needs review', verdict('customer_id'), { c: 'internal', s: 'medium', cat: 'identifier', rev: true });
check('id exact', verdict('id'), { c: 'internal', s: 'low', cat: 'identifier', rev: true });
check('created_at', verdict('created_at'), { c: 'internal', s: 'none', cat: 'technical', rev: true });
check('name uncertain', verdict('name'), { c: 'confidential', s: 'medium', cat: 'contact', rev: true });

// --- word-boundary safety: no false positives ---
check('hotel is not telephone', verdict('hotel'), null);
check('shipping is not ip', verdict('shipping'), null);
check('foo_bar unknown', verdict('foo_bar'), null);

// --- rollup ---
check('rollup max severity', C.rollupAsset(
  [{ classification: 'internal', sensitivity: 'low' }, { classification: 'confidential', sensitivity: 'high' }],
  { classification: 'internal', sensitivity: 'none' },
), { classification: 'confidential', sensitivity: 'high' });
check('rollup empty falls back', C.rollupAsset([], { classification: 'internal', sensitivity: 'none' }),
  { classification: 'internal', sensitivity: 'none' });

// --- findings mapping (must fit the DB check constraints) ---
const DB_FINDING_TYPES = new Set(['pii', 'financial', 'credential', 'source_code', 'healthcare', 'confidential', 'secret']);
const DB_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const mkCol = (over) => ({
  name: 'x', classification: 'confidential', sensitivity: 'high', confidence: 0.95,
  rule: 'R', category: 'pii', needs_review: false, classified_by: 'rules-v1', ...over,
});
const f1 = C.columnToFinding('public.customers', mkCol({ name: 'email', category: 'pii' }));
check('email finding', { t: f1.finding_type, s: f1.severity }, { t: 'pii', s: 'high' });
const f2 = C.columnToFinding('public.payments', mkCol({ name: 'card_number', classification: 'restricted', sensitivity: 'critical', category: 'financial' }));
check('card_number finding', { t: f2.finding_type, s: f2.severity }, { t: 'financial', s: 'critical' });
check('identifier makes no finding', C.columnToFinding('t', mkCol({ name: 'customer_id', classification: 'internal', sensitivity: 'medium', category: 'identifier' })), null);
check('unknown makes no finding', C.columnToFinding('t', mkCol({ name: 'foo', classification: 'internal', sensitivity: 'none', confidence: null, category: null })), null);
for (const ft of ['pii', 'financial', 'credential', 'healthcare', 'confidential']) {
  if (!DB_FINDING_TYPES.has(ft)) { failed += 1; console.error(`FAIL finding_type ${ft} not allowed by DB`); }
  else passed += 1;
}
for (const s of ['high', 'critical']) {
  if (!DB_SEVERITIES.has(s)) { failed += 1; console.error(`FAIL severity ${s} not allowed by DB`); }
  else passed += 1;
}

// --- edge functions wire up the shared modules ---
for (const f of ['supabase/functions/discover-postgres/index.ts', 'supabase/functions/classify-assets/index.ts']) {
  const body = readFileSync(f, 'utf8');
  check(`${f} imports classify`, body.includes("../_shared/classify.ts"), true);
  check(`${f} imports findings`, body.includes("../_shared/findings.ts"), true);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
