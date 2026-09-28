// Verifies src/lib/parseRule.ts (deterministic plain-English rule parser):
// transpiles the TypeScript with the project's compiler, runs it in Node,
// and asserts parsing outcomes for representative sentences.
// Run: node scripts/verify-parser.mjs
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

const require = createRequire(join(process.cwd(), 'package.json'));
const ts = require('typescript');
const src = readFileSync('src/lib/parseRule.ts', 'utf8');
const { outputText, diagnostics } = ts.transpileModule(src, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
  reportDiagnostics: true,
});
const fatal = (diagnostics ?? []).filter((d) => d.category === ts.DiagnosticCategory.Error);
if (fatal.length > 0) {
  console.error('TypeScript errors in parseRule.ts:');
  for (const d of fatal) console.error(' -', ts.flattenDiagnosticMessageText(d.messageText, '\n'));
  process.exit(1);
}
// The parser imports types from policyService (type-only) — strip the import.
const js = outputText.replace(/import .* from '.*policyService';?/g, '');
const dir = join(tmpdir(), 'verify-parser');
mkdirSync(dir, { recursive: true });
const file = join(dir, 'parseRule.mjs');
writeFileSync(file, js);
const { parseRuleSentence, summarizeParsed, suggestPolicyName } = await import(pathToFileURL(file).href);

const cond = (rule, field) => rule.conditions.find((c) => c.field === field);

// 1. Basic block + content categories + external AI
let r = parseRuleSentence('block emails and phone numbers sent to external AI');
expect(r.action === 'block', 'action: block detected');
expect(r.actionSource === 'found', 'action source: found');
expect(cond(r, 'content.category')?.operator === 'in', 'content condition uses "in"');
expect(JSON.stringify(cond(r, 'content.category')?.value) === JSON.stringify(['email', 'phone']), 'content values email+phone');
expect(cond(r, 'ai.is_external')?.value === true, 'external AI detected');

// 2. Ask-me-first phrasing
r = parseRuleSentence('ask me first before sharing credit card numbers');
expect(r.action === 'require_approval', 'action: ask me → require_approval');
expect(cond(r, 'content.category')?.value?.includes('credit_card'), 'credit card detected');

// 3. Hide/mask phrasing
r = parseRuleSentence('hide secrets and api keys');
expect(r.action === 'mask', 'action: hide → mask');
expect(cond(r, 'content.category')?.value?.includes('secret'), 'secret detected');
expect(cond(r, 'content.category')?.value?.includes('api_key'), 'api key detected');

// 4. Classification levels
r = parseRuleSentence('stop anything confidential or restricted');
expect(r.action === 'block', 'action: stop → block');
expect(JSON.stringify(cond(r, 'data.classification')?.value) === JSON.stringify(['confidential', 'restricted']), 'classification confidential+restricted');

// 5. Except/unless negation
r = parseRuleSentence('block emails except internal ai');
expect(cond(r, 'content.category')?.operator === 'in', 'positive clause stays "in"');
const prov = cond(r, 'ai.provider');
expect(prov?.operator === 'not_in' && prov?.value?.includes('internal'), 'except internal ai → provider not_in internal');

// 6. Provider names
r = parseRuleSentence('block anything sent to chatgpt');
expect(cond(r, 'ai.provider')?.value?.includes('openai'), 'chatgpt → openai provider');

// 7. Sensitivity
r = parseRuleSentence('require approval for high sensitivity data');
expect(r.action === 'require_approval', 'action: require approval');
expect(cond(r, 'data.sensitivity_level')?.value?.[0] === 'high', 'high sensitivity detected');

// 8. Default action when none named
r = parseRuleSentence('emails to external ai');
expect(r.action === 'block' && r.actionSource === 'default', 'defaults to block with warning');
expect(r.warnings.length > 0, 'warning emitted for default action');

// 9. Gibberish → no conditions + guidance warning
r = parseRuleSentence('hello world how are you');
expect(r.conditions.length === 0, 'no conditions for gibberish');
expect(r.warnings.some((w) => w.includes('Couldn')), 'guidance warning for empty parse');

// 10. Summary + name
r = parseRuleSentence('block ssn and passwords for external ai');
const summary = summarizeParsed(r);
expect(summary.includes('stop it'), 'summary mentions stopping');
expect(summary.includes('government IDs') || summary.includes('secrets'), 'summary names findings');
const name = suggestPolicyName(r);
expect(name.startsWith('Block'), 'suggested name starts with Block');
expect(name.length <= 80, 'suggested name capped at 80 chars');

// 11. Synonyms: ssn, private
r = parseRuleSentence('deny anything with ssn or private data');
expect(r.action === 'block', 'action: deny → block');
expect(cond(r, 'content.category')?.value?.includes('gov_id'), 'ssn → gov_id');
expect(cond(r, 'data.classification')?.value?.includes('confidential'), 'private → confidential');

console.log(failures === 0 ? '\nAll parser assertions passed.' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
