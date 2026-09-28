// Unit tests for the gateway's shared modules (no network, no database):
//   - providers.ts: adapters, retry/backoff, Retry-After, timeouts
//   - pricing.ts:   cost estimation
//   - detect.ts:    detectors added in the production-hardening pass
// Run: node scripts/verify-providers.mjs
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const require = createRequire(join(process.cwd(), 'package.json'));
const ts = require('typescript');
const outDir = join(tmpdir(), 'allowbase-provider-tests');
mkdirSync(outDir, { recursive: true });

async function load(file) {
  const { outputText } = ts.transpileModule(readFileSync(file, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  const target = join(outDir, file.replace(/[/\\]/g, '_').replace(/\.ts$/, '.mjs'));
  writeFileSync(target, outputText);
  return import(pathToFileURL(target).href + `?t=${Date.now()}`);
}

let failures = 0;
function expect(cond, label) {
  console.log((cond ? 'ok   ' : 'FAIL ') + label);
  if (!cond) failures++;
}

const P = await load('supabase/functions/_shared/providers.ts');
const C = await load('supabase/functions/_shared/pricing.ts');
const D = await load('supabase/functions/_shared/detect.ts');

// ------------------------------------------------------------------ adapters
const msgs = [
  { role: 'system', content: 'Be brief.' },
  { role: 'user', content: 'Hi' },
  { role: 'user', content: 'again' },
];
{
  const req = P.ADAPTERS.openai.build('gpt-4o-mini', msgs, 'KEY', null);
  expect(req.url === 'https://api.openai.com/v1/chat/completions', 'openai: default URL');
  expect(req.headers.Authorization === 'Bearer KEY', 'openai: bearer auth');
  const custom = P.ADAPTERS.custom.build('m', msgs, 'KEY', 'https://llm.internal/v1/');
  expect(custom.url === 'https://llm.internal/v1/chat/completions', 'custom: base URL trailing slash trimmed');
  const parsed = P.ADAPTERS.openai.parse({ choices: [{ message: { content: 'yo' } }], usage: { prompt_tokens: 12, completion_tokens: 3 } });
  expect(parsed.text === 'yo' && parsed.usage.inputTokens === 12 && parsed.usage.outputTokens === 3, 'openai: parse text + usage');
}
{
  const req = P.ADAPTERS.anthropic.build('claude-3-5-haiku', msgs, 'KEY', null);
  expect(req.body.system === 'Be brief.', 'anthropic: system prompt lifted');
  expect(req.body.messages.length === 1 && req.body.messages[0].content === 'Hi\nagain', 'anthropic: same-role messages merged');
  const parsed = P.ADAPTERS.anthropic.parse({ content: [{ type: 'text', text: 'a' }, { type: 'tool_use' }, { type: 'text', text: 'b' }], usage: { input_tokens: 5, output_tokens: 2 } });
  expect(parsed.text === 'ab' && parsed.usage.inputTokens === 5, 'anthropic: only text blocks, usage parsed');
}
{
  const req = P.ADAPTERS.gemini.build('gemini-2.0-flash', msgs, 'KEY', null);
  expect(req.headers['x-goog-api-key'] === 'KEY' && !req.url.includes('KEY'), 'gemini: key in header, never in URL');
  const parsed = P.ADAPTERS.gemini.parse({ candidates: [{ content: { parts: [{ text: 'x' }] } }], usageMetadata: { promptTokenCount: 7, candidatesTokenCount: 1 } });
  expect(parsed.text === 'x' && parsed.usage.outputTokens === 1, 'gemini: parse text + usage');
}

// ------------------------------------------------------------------ retry logic
expect(P.isRetryableStatus(429) && P.isRetryableStatus(503) && !P.isRetryableStatus(400) && !P.isRetryableStatus(401), 'retryable statuses');
expect(P.parseRetryAfter('2') === 2000 && P.parseRetryAfter('999') === 30000 && P.parseRetryAfter(null) === null, 'Retry-After seconds parsed and capped');
expect(P.backoffDelay(1, null, () => 0.999) < 300 && P.backoffDelay(10, null, () => 0.999) < 5000, 'backoff capped with jitter');
expect(P.backoffDelay(1, 1500) === 1500, 'backoff honours Retry-After');

function fakeFetch(responses) {
  let i = 0;
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    const next = responses[Math.min(i++, responses.length - 1)];
    if (next instanceof Error) throw next;
    return new Response(JSON.stringify(next.body ?? {}), { status: next.status, headers: next.headers ?? {} });
  };
  return { impl, calls };
}
const ok = { status: 200, body: { choices: [{ message: { content: 'done' } }], usage: { prompt_tokens: 1, completion_tokens: 1 } } };
const base = { adapter: P.ADAPTERS.openai, apiKey: 'K', baseUrl: null, model: 'gpt-4o-mini', messages: msgs, sleep: async () => {}, random: () => 0 };

{
  const f = fakeFetch([{ status: 503 }, { status: 429, headers: { 'retry-after': '0' } }, ok]);
  const out = await P.callWithRetry({ ...base, fetchImpl: f.impl });
  expect(!P.isFailedCall(out) && out.attempts === 3 && out.result.text === 'done', 'retry: recovers after 503 then 429');
}
{
  const f = fakeFetch([{ status: 401 }, ok]);
  const out = await P.callWithRetry({ ...base, fetchImpl: f.impl });
  expect(P.isFailedCall(out) && out.attempts === 1 && out.error.code === 'provider_rejected', 'retry: 401 is not retried');
}
{
  const f = fakeFetch([{ status: 500 }]);
  const out = await P.callWithRetry({ ...base, fetchImpl: f.impl, maxAttempts: 2 });
  expect(P.isFailedCall(out) && out.attempts === 2 && f.calls.length === 2, 'retry: gives up after maxAttempts');
}
{
  const timeout = Object.assign(new Error('timed out'), { name: 'TimeoutError' });
  const f = fakeFetch([timeout, ok]);
  const out = await P.callWithRetry({ ...base, fetchImpl: f.impl });
  expect(!P.isFailedCall(out) && out.attempts === 2, 'retry: timeouts are retried');
}
{
  const f = fakeFetch([{ status: 200, body: 'not-json' }]);
  const impl = async () => new Response('<html>', { status: 200 });
  const out = await P.callWithRetry({ ...base, fetchImpl: impl });
  expect(P.isFailedCall(out) && out.error.code === 'bad_response', 'retry: invalid JSON is a non-retryable failure');
  void f;
}
{
  const f = fakeFetch([{ status: 502 }]);
  const out = await P.callWithRetry({ ...base, fetchImpl: f.impl, deadlineMs: 100 });
  expect(P.isFailedCall(out) && f.calls.length === 0, 'retry: exhausted deadline makes no call');
}
{
  const f = fakeFetch([{ status: 400, body: { error: { message: 'bad key sk-SECRET' } } }]);
  const out = await P.callWithRetry({ ...base, fetchImpl: f.impl });
  expect(P.isFailedCall(out) && !out.error.message.includes('SECRET'), 'errors never echo provider body');
}

// ------------------------------------------------------------------ pricing
expect(C.estimateCostUsd('openai', 'gpt-4o-mini-2024-07-18', 1_000_000, 0) === 0.15, 'pricing: dated snapshot resolves to family');
expect(C.estimateCostUsd('openai', 'gpt-4o', 1000, 1000) === 0.0125, 'pricing: gpt-4o not confused with gpt-4o-mini');
expect(C.estimateCostUsd('anthropic', 'claude-sonnet-4-20250514', 1000, 500) === 0.0105, 'pricing: anthropic');
expect(C.estimateCostUsd('gemini', 'models/gemini-2.5-flash', 2000, 0) === 0.0006, 'pricing: gemini models/ prefix stripped');
expect(C.estimateCostUsd('custom', 'gpt-4.1-mini', 1_000_000, 1_000_000) === 2, 'pricing: custom falls back to openai table');
expect(C.estimateCostUsd('openai', 'unknown-model', 10, 10) === null, 'pricing: unknown model -> null');
expect(C.estimateCostUsd('openai', 'gpt-4o', null, null) === null, 'pricing: missing usage -> null');

// ------------------------------------------------------------------ new detectors
const cats = (text) => D.detectSensitiveContent(text).map((f) => f.category).sort().join(',');
expect(cats('Wire to DE89 3704 0044 0532 0130 00 today') .includes('iban'), 'detect: valid IBAN (spaced)');
expect(cats('Ref GB82WEST12345698765432') === 'iban', 'detect: valid IBAN (compact)');
expect(!cats('Ref GB00WEST12345698765432').includes('iban'), 'detect: IBAN with bad checksum ignored');
expect(cats('Server at 10.24.3.201 is down') === 'ip_address', 'detect: IPv4 address');
expect(cats('Upgrade to v1.2.3.4 now') === '', 'detect: version strings are not IPs');
expect(cats('Bad octet 999.1.1.1') === '', 'detect: out-of-range octets ignored');
expect(cats('key: sk-proj-abcdefghijklmnopqrstuvwxyz0123') === 'api_key', 'detect: OpenAI project key');
expect(cats('use sk-ant-api03-abcdefghijklmnopqrstuvwx') === 'api_key', 'detect: Anthropic key');
expect(cats('token xoxb-1234567890-abcdefghij') === 'api_key', 'detect: Slack token');
expect(cats('maps AIzaSyA1234567890abcdefghijklmnopqrstuv') === 'api_key', 'detect: Google API key');
expect(cats('The task-list has sk-items') === '', 'detect: short sk- words are not keys');
const masked = D.maskSensitiveContent('IBAN GB82WEST12345698765432 from 10.0.0.1');
expect(masked.masked === 'IBAN [redacted:iban] from [redacted:ip_address]', 'mask: new categories redacted');

if (failures > 0) {
  console.error(`\n${failures} provider/pricing/detector check(s) failed.`);
  process.exit(1);
}
console.log('\nProvider, pricing and detector checks passed.');
