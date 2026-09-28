// Verifies Phase D (streaming output inspection) end to end:
//   Unit tests for supabase/functions/_shared/streamInspect.ts (transpiled
//   with the project's TypeScript, run in Node). detect.ts and threat.ts are
//   transpiled too since streamInspect.ts imports from both.
//   - clean streams pass through whole (after finalize)
//   - secrets split across chunk boundaries are caught via the overlap buffer
//   - critical findings terminate the stream and audit (categories only)
//   - high findings are redacted in flight
//   - high/critical threat patterns terminate (response-side blocking)
//   - medium findings pass through; token ids pass through untouched
//   - adversarial chunk-splitting residual is locked in as documented behavior
// Run: node scripts/verify-streaming.mjs
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
const dir = join(tmpdir(), 'dataplane-stream-test');
mkdirSync(dir, { recursive: true });

function transpile(relPath, outName, fixImports) {
  let src = readFileSync(relPath, 'utf8');
  if (fixImports) src = fixImports(src);
  const { outputText, diagnostics } = ts.transpileModule(src, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
    reportDiagnostics: true,
  });
  const fatal = (diagnostics ?? []).filter((d) => d.category === ts.DiagnosticCategory.Error);
  if (fatal.length > 0) {
    console.error(`TypeScript errors in ${relPath}:`);
    for (const d of fatal) console.error(' -', ts.flattenDiagnosticMessageText(d.messageText, ' '));
    process.exit(1);
  }
  const out = join(dir, outName);
  writeFileSync(out, outputText);
  return out;
}

transpile('supabase/functions/_shared/detect.ts', 'detect.mjs');
transpile('supabase/functions/_shared/threat.ts', 'threat.mjs');
const streamPath = transpile(
  'supabase/functions/_shared/streamInspect.ts',
  'streamInspect.mjs',
  (src) =>
    src.replace("from './detect.ts'", "from './detect.mjs'").replace("from './threat.ts'", "from './threat.mjs'"),
);
const S = await import(pathToFileURL(streamPath).href);

expect(S.STREAM_OVERLAP_BYTES === 2048, 'overlap buffer is 2 KB');
expect(S.STREAM_INSPECTOR_VERSION === 'stream-v1', 'inspector version stamped');

// 1. Clean stream passes through whole after finalize.
{
  const ins = new S.StreamInspector(32);
  let out = '';
  for (const c of ['Hello, this is ', 'a perfectly benign ', 'model response.']) {
    const r = ins.inspect(c);
    expect(!r.terminated, 'clean chunk not terminated');
    out += r.output;
  }
  out += ins.finalize().output;
  expect(out === 'Hello, this is a perfectly benign model response.', 'clean stream reassembles exactly');
}

// 2. Critical secret split across a chunk boundary is caught.
{
  const ins = new S.StreamInspector(32);
  const r1 = ins.inspect('Here is the key: AKIAIOSFODNN7EXA');
  expect(!r1.terminated, 'partial secret not yet terminated');
  const r2 = ins.inspect('MPLE for your records.');
  expect(r2.terminated, 'critical secret completed across chunks terminates');
  expect(r2.output === '', 'terminating chunk is dropped');
  expect(r2.terminateReason !== null, 'terminate reason set');
  const fin = ins.finalize();
  expect(fin.terminated, 'finalize stays terminated');
  const sum = ins.summary();
  expect(sum.terminated && Object.keys(sum.countsByCategory).includes('api_key'), 'summary records api_key category');
  expect(!JSON.stringify(sum).includes('AKIAIOSFODNN7EXAMPLE'), 'summary never contains the raw secret');
}

// 3. inspect() after termination stays terminated with no output.
{
  const ins = new S.StreamInspector(32);
  ins.inspect('AKIAIOSFODNN7EXAMPLE');
  const r = ins.inspect('more text');
  expect(r.terminated && r.output === '', 'post-termination inspect is a no-op');
}

// 4. High finding (SSN) is redacted in flight, stream continues.
{
  const ins = new S.StreamInspector(16);
  let out = '';
  // Push enough text that the SSN leaves the overlap region.
  out += ins.inspect('Customer SSN is 123-45-6789').output;
  out += ins.inspect(' and that is all the padding needed to push it out!!').output;
  out += ins.finalize().output;
  expect(out.includes('[redacted:gov_id]'), 'SSN redacted in streamed output');
  expect(!out.includes('123-45-6789'), 'raw SSN never emitted');
  const sum = ins.summary();
  expect(!sum.terminated && sum.redactions >= 1, 'stream continued after redaction');
}

// 5. High-severity threat pattern terminates (response-side blocking).
{
  const ins = new S.StreamInspector(32);
  const r = ins.inspect('Sure, entering DAN mode now.');
  expect(r.terminated, 'jailbreak pattern in model output terminates');
  expect(r.findings.some((f) => f.category === 'jailbreak'), 'jailbreak finding recorded');
  expect(!JSON.stringify(r.findings).includes('DAN mode now'), 'findings carry no raw values');
}

// 6. Medium findings (email) pass through; counted only.
{
  const ins = new S.StreamInspector(16);
  let out = '';
  out += ins.inspect('Contact jane.doe@example.com ').output;
  out += ins.inspect('for helpxxxxxxxxxxxxxxxxxxxxxxxxxxxx').output;
  out += ins.finalize().output;
  expect(out.includes('jane.doe@example.com'), 'medium finding passes through in streaming mode');
  expect(!ins.summary().terminated, 'no termination for medium findings');
  expect(ins.summary().countsByCategory.email >= 1, 'email counted in summary');
}

// 7. Token ids pass through the inspector untouched.
{
  const ins = new S.StreamInspector(16);
  const tid = 'abt_tok_AAAAAAAAAAAAAAAAAAAAAA';
  let out = '';
  out += ins.inspect(`value is ${tid} ok `).output;
  out += ins.inspect('padding padding padding padding!').output;
  out += ins.finalize().output;
  expect(out.includes(tid), 'token id survives inspection untouched');
  expect(!ins.summary().terminated, 'token id triggers nothing');
}

// 8. Tiny overlap still catches a boundary split (overlap = 8).
{
  const ins = new S.StreamInspector(8);
  ins.inspect('key=AKIAIOSF');
  const r = ins.inspect('ODNN7EXAMPLE!');
  expect(r.terminated, '8-byte overlap catches split at exact boundary');
}

// 9. Documented residual: padding larger than the overlap between the two
//    halves defeats reassembly — the first half is already emitted. This
//    test locks in the honest behavior: no silent claim of full protection.
{
  const ins = new S.StreamInspector(16);
  let out = '';
  out += ins.inspect('first half AKIAIOSF' + 'x'.repeat(64)).output;
  const r = ins.inspect('ODNN7EXAMPLE second half');
  out += r.output + ins.finalize().output;
  expect(!r.terminated, 'halves separated by >overlap padding are not joined (documented residual)');
  expect(out.includes('AKIAIOSF'), 'first half was already emitted and cannot be recalled');
}

// 10. finalize() on a clean stream flushes the held-back tail.
{
  const ins = new S.StreamInspector(2048);
  const r = ins.inspect('short');
  expect(r.output === '', 'everything held back while under overlap size');
  const fin = ins.finalize();
  expect(fin.output === 'short' && !fin.terminated, 'finalize flushes the tail');
}

// 11. Critical finding in the final tail terminates at finalize.
{
  const ins = new S.StreamInspector(2048);
  ins.inspect('nothing to see here, key is AKIAIOSFODNN7EXAMPLE');
  const fin = ins.finalize();
  expect(fin.terminated && fin.output === '', 'critical in tail terminates at finalize');
}

// 12. Empty chunks are harmless.
{
  const ins = new S.StreamInspector(16);
  const r = ins.inspect('');
  expect(!r.terminated && r.output === '', 'empty chunk is a no-op');
  expect(ins.finalize().output === '', 'finalize on empty stream is clean');
}

if (failures > 0) {
  console.error(`\n${failures} streaming check(s) FAILED`);
  process.exit(1);
}
console.log('\nAll streaming checks passed.');
