// Interception test rig: runs the REAL AllowBase detection engine
// (supabase/functions/_shared/detect.ts, transpiled like verify-detect.mjs)
// against pasted/PDF text, then evaluates the test policy set.
// Usage:
//   node scripts/test-interception.mjs "text to test"
//   node scripts/test-interception.mjs --file /path/to/extracted.txt
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// --- Load the real detector (same code the edge function runs) ---
const src = readFileSync(new URL('../supabase/functions/_shared/detect.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext } }).outputText;
const tmpFile = join(tmpdir(), `detect-test-${Date.now()}.mjs`);
require('node:fs').writeFileSync(tmpFile, js);
const { detectSensitiveContent, maskSensitiveContent } = await import(pathToFileURL(tmpFile).href);

// --- The rule book for this test (mirrors product policy semantics:
//     first matching policy wins, block beats mask beats allow) ---
// Net 1: context rule — student records never go to external AI, no matter
//        what the text contains. This catches what the scanner cannot
//        (names, roll numbers, marks, grades have no detectable pattern).
// Net 2: content rules — scanner findings trigger block/mask.
const POLICIES = [
  {
    name: 'My Results to ChatGPT',
    kind: 'context',
    when: (ctx) => ctx.source === 'student_records' && ctx.model === 'chatgpt' && ctx.purpose === 'personal_use',
    action: 'allow',
    reason: 'You chose to share your own results with ChatGPT. Owner override.',
  },
  {
    name: 'Protect Student Records',
    kind: 'context',
    when: (ctx) => ctx.source === 'student_records' && ctx.destination === 'external',
    action: 'block',
    reason: 'Student records must never be sent to external AI systems.',
  },
  {
    name: 'Block Student PII',
    kind: 'content',
    when: ['email', 'phone'],
    action: 'block',
    reason: 'Student contact details must never reach the AI.',
  },
  {
    name: 'Mask Secrets in Transit',
    kind: 'content',
    when: ['api_key', 'private_key', 'jwt', 'secret', 'credit_card', 'gov_id'],
    action: 'mask',
    reason: 'Secrets are masked before the AI sees them.',
  },
];

// --- Input ---
const args = process.argv.slice(2);
let text = '';
const ctx = { source: 'general', purpose: 'general', destination: 'external', model: 'unknown' };
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--file') text = readFileSync(args[++i], 'utf8');
  else if (args[i] === '--source') ctx.source = args[++i];
  else if (args[i] === '--purpose') ctx.purpose = args[++i];
  else if (args[i] === '--destination') ctx.destination = args[++i];
  else if (args[i] === '--model') ctx.model = args[++i];
  else text += (text ? ' ' : '') + args[i];
}
if (!text.trim()) {
  console.error('Give me text to test: node scripts/test-interception.mjs "some text"');
  process.exit(1);
}

// --- Step 1: scan (the gatekeeper's metal detector) ---
const findings = detectSensitiveContent(text);
const categories = [...new Set(findings.map((f) => f.category))];

// --- Step 2: evaluate policies in order ---
let decision = { action: 'allow', policy: null, reason: 'No policy matched. Request allowed.' };
for (const policy of POLICIES) {
  const matched =
    policy.kind === 'context' ? policy.when(ctx) : policy.when.some((c) => categories.includes(c));
  if (matched) {
    decision = { action: policy.action, policy: policy.name, reason: policy.reason };
    break;
  }
}

// --- Step 3: report ---
console.log('=== ALLOWBASE INTERCEPTION TEST ===');
console.log(`Context: source=${ctx.source} purpose=${ctx.purpose} destination=${ctx.destination}`);
console.log(`Scanned ${text.length} characters.`);
console.log('');
console.log('Detections:');
if (findings.length === 0) {
  console.log('  (none — the scanner found nothing sensitive)');
} else {
  for (const f of findings) {
    console.log(`  - ${f.category} (${f.severity}, ${f.count} match${f.count === 1 ? '' : 'es'})`);
  }
}
console.log('');
console.log(`DECISION: ${decision.action.toUpperCase()}`);
console.log(`Policy: ${decision.policy ?? '—'}`);
console.log(`Reason: ${decision.reason}`);
if (decision.action === 'mask') {
  const masked = maskSensitiveContent(text);
  console.log('');
  console.log('Masked text sent to AI instead:');
  console.log(masked.text.slice(0, 600));
  console.log(`(${masked.replacements} value(s) masked)`);
}
if (decision.action === 'block') {
  console.log('');
  console.log('The AI never saw this text. Nothing left the boundary.');
}
