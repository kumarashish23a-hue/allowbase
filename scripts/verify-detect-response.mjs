// Verifies the Feature 3 additions to supabase/functions/_shared/detect.ts:
//   - Indian PAN detection (gov_id)
//   - Indian Aadhaar detection (gov_id)
//   - IBAN detection with mod-97 checksum validation (iban category)
//   - Masking covers the new patterns (no raw values leak)
//   - Existing detectors keep working
// Transpiles the shared module with the project's TypeScript and runs it in
// Node — same pattern as scripts/verify-detect.mjs (A-section).
// Run: node scripts/verify-detect-response.mjs
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

let failures = 0;
function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) failures++;
}

// ---------------------------------------------------------------- transpile
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
const dir = join(tmpdir(), 'dataplane-detect-response-test');
mkdirSync(dir, { recursive: true });
const compiled = join(dir, 'detect.mjs');
writeFileSync(compiled, outputText);
const D = await import(pathToFileURL(compiled).href);

// Reference mod-97 implementation (independent of detect.ts) so the test
// verifies its own fixtures before asserting on the detector.
function refMod97(iban) {
  const r = iban.slice(4) + iban.slice(0, 4);
  let rem = 0;
  for (const ch of r) {
    const c = ch.charCodeAt(0);
    const v = c >= 65 && c <= 90 ? c - 55 : c - 48;
    for (const d of String(v)) rem = (rem * 10 + Number(d)) % 97;
  }
  return rem;
}

// ---------------------------------------------------------------- (a) PAN
let f = D.detectSensitiveContent('Please share PAN ABCDE1234F for KYC verification.');
const pan = f.find((x) => x.category === 'gov_id');
expect(!!pan && pan.severity === 'high' && pan.confidence >= 0.85, '(a) PAN ABCDE1234F detected as gov_id/high');
expect(!JSON.stringify(f).includes('ABCDE1234F'), '(a) findings never contain the raw PAN');

// ---------------------------------------------------------------- (b) Aadhaar
f = D.detectSensitiveContent('Aadhaar 2345 6789 0123 is linked to the account.');
const aadhaar = f.find((x) => x.category === 'gov_id');
expect(!!aadhaar && aadhaar.severity === 'high' && aadhaar.confidence >= 0.8, '(b) 12-digit Aadhaar detected as gov_id/high');
expect(!f.some((x) => x.category === 'credit_card'), '(b) Aadhaar digits are not misdetected as a credit card');
expect(!JSON.stringify(f).includes('2345'), '(b) findings never contain the raw Aadhaar digits');

// ------------------------------------------------------------ (c) valid IBAN
const VALID_IBAN_COMPACT = 'GB29NWBK60161331926819';
expect(refMod97(VALID_IBAN_COMPACT) === 1, '(c) fixture IBAN passes mod-97 (sanity)');
f = D.detectSensitiveContent('Please transfer to IBAN GB29 NWBK 6016 1331 9268 19 today.');
const iban = f.find((x) => x.category === 'iban');
expect(!!iban && iban.severity === 'high' && iban.confidence >= 0.85, '(c) valid spaced IBAN detected as iban/high');
expect(!JSON.stringify(f).includes('GB29'), '(c) findings never contain the raw IBAN');

f = D.detectSensitiveContent('IBAN:' + VALID_IBAN_COMPACT);
expect(f.some((x) => x.category === 'iban'), '(c) compact IBAN detected as iban');

// ---------------------------------------------------------- (d) invalid IBAN
const BAD_IBAN_COMPACT = 'GB29NWBK60161331926818';
expect(refMod97(BAD_IBAN_COMPACT) !== 1, '(d) tampered IBAN fails mod-97 (sanity)');
f = D.detectSensitiveContent('IBAN GB29 NWBK 6016 1331 9268 18 looks wrong.');
expect(!f.some((x) => x.category === 'iban'), '(d) IBAN with bad checksum is NOT detected');

// ------------------------------------------------------- (d2) masking of new patterns
const planted = 'PAN ABCDE1234F, aadhaar 2345 6789 0123, iban GB29 NWBK 6016 1331 9268 19.';
const m = D.maskSensitiveContent(planted);
expect(m.maskedCount >= 3, '(d2) all three planted values are masked');
expect(!m.masked.includes('ABCDE1234F'), '(d2) masked output hides the PAN');
expect(!m.masked.includes('2345') && !m.masked.includes('6789') && !m.masked.includes('0123'), '(d2) masked output hides Aadhaar digits');
expect(!m.masked.includes('GB29') && !m.masked.includes('NWBK') && !m.masked.includes('9268'), '(d2) masked output hides the IBAN');
expect(m.categories.includes('gov_id') && m.categories.includes('iban'), '(d2) mask reports gov_id and iban categories');

// ------------------------------------------------- (e) existing detectors
f = D.detectSensitiveContent('Contact jane@example.com about key AKIAIOSFODNN7EXAMPLE.');
expect(f.some((x) => x.category === 'email'), '(e) email detector still works');
expect(f.some((x) => x.category === 'api_key' && x.severity === 'critical'), '(e) api_key detector still works');
expect(D.DETECTOR_VERSION === 'regex-v2', '(e) DETECTOR_VERSION bumped to regex-v2');

if (failures > 0) {
  console.error(`${failures} assertion(s) failed`);
  process.exit(1);
}
console.log('ok    all response-detection assertions passed');
