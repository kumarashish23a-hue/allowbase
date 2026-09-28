// Provider abstraction for the AI gateway.
//
// Each provider is an adapter that knows how to build a request and parse a
// response; the gateway only talks to `callWithRetry`. Retries use capped
// exponential backoff with full jitter and honour Retry-After. Zero runtime
// dependencies so it runs in Deno and can be unit-tested in Node.

export const PROVIDER_IDS = ['openai', 'anthropic', 'gemini', 'custom'] as const;
export type ProviderId = (typeof PROVIDER_IDS)[number];

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface ProviderUsage {
  inputTokens: number | null;
  outputTokens: number | null;
  raw: Record<string, unknown> | null;
}

export interface ProviderResult {
  text: string;
  usage: ProviderUsage;
}

export class ProviderError extends Error {
  readonly status: number | null;
  readonly retryable: boolean;
  readonly retryAfterMs: number | null;
  readonly code: string;

  constructor(message: string, opts: { status?: number | null; retryable: boolean; retryAfterMs?: number | null; code: string }) {
    super(message);
    this.name = 'ProviderError';
    this.status = opts.status ?? null;
    this.retryable = opts.retryable;
    this.retryAfterMs = opts.retryAfterMs ?? null;
    this.code = opts.code;
  }
}

interface BuiltRequest {
  url: string;
  headers: Record<string, string>;
  body: unknown;
}

export interface ProviderAdapter {
  id: ProviderId;
  build(model: string, messages: ChatMessage[], apiKey: string, baseUrl: string | null): BuiltRequest;
  parse(data: unknown): ProviderResult;
}

/** Merge consecutive same-role messages; Anthropic and Gemini reject role repeats. */
export function normalizeRoles(messages: ChatMessage[]): ChatMessage[] {
  const out: ChatMessage[] = [];
  for (const m of messages) {
    const last = out[out.length - 1];
    if (last && last.role === m.role) last.content += '\n' + m.content;
    else out.push({ ...m });
  }
  return out;
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

const openAiCompatible = (id: ProviderId): ProviderAdapter => ({
  id,
  build(model, messages, apiKey, baseUrl) {
    const base = (baseUrl ?? 'https://api.openai.com/v1').replace(/\/$/, '');
    return {
      url: `${base}/chat/completions`,
      headers: { Authorization: `Bearer ${apiKey}` },
      body: { model, messages: messages.map((m) => ({ role: m.role, content: m.content })) },
    };
  },
  parse(data) {
    const d = data as { choices?: { message?: { content?: string } }[]; usage?: Record<string, unknown> };
    return {
      text: d.choices?.[0]?.message?.content ?? '',
      usage: {
        inputTokens: num(d.usage?.prompt_tokens),
        outputTokens: num(d.usage?.completion_tokens),
        raw: d.usage ?? null,
      },
    };
  },
});

const anthropic: ProviderAdapter = {
  id: 'anthropic',
  build(model, messages, apiKey) {
    const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
    const convo = normalizeRoles(messages.filter((m) => m.role !== 'system'));
    return {
      url: 'https://api.anthropic.com/v1/messages',
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: { model, max_tokens: 2048, ...(system ? { system } : {}), messages: convo },
    };
  },
  parse(data) {
    const d = data as { content?: { type?: string; text?: string }[]; usage?: Record<string, unknown> };
    return {
      text: (d.content ?? []).filter((b) => b.type === 'text').map((b) => b.text ?? '').join(''),
      usage: {
        inputTokens: num(d.usage?.input_tokens),
        outputTokens: num(d.usage?.output_tokens),
        raw: d.usage ?? null,
      },
    };
  },
};

const gemini: ProviderAdapter = {
  id: 'gemini',
  build(model, messages, apiKey) {
    const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
    const contents = normalizeRoles(messages.filter((m) => m.role !== 'system')).map((m) => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));
    return {
      url: `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      headers: { 'x-goog-api-key': apiKey },
      body: { ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}), contents },
    };
  },
  parse(data) {
    const d = data as {
      candidates?: { content?: { parts?: { text?: string }[] } }[];
      usageMetadata?: Record<string, unknown>;
    };
    return {
      text: (d.candidates?.[0]?.content?.parts ?? []).map((p) => p.text ?? '').join(''),
      usage: {
        inputTokens: num(d.usageMetadata?.promptTokenCount),
        outputTokens: num(d.usageMetadata?.candidatesTokenCount),
        raw: d.usageMetadata ?? null,
      },
    };
  },
};

export const ADAPTERS: Record<ProviderId, ProviderAdapter> = {
  openai: openAiCompatible('openai'),
  custom: openAiCompatible('custom'),
  anthropic,
  gemini,
};

const RETRYABLE_STATUS = new Set([408, 409, 425, 429, 500, 502, 503, 504, 529]);

export function isRetryableStatus(status: number): boolean {
  return RETRYABLE_STATUS.has(status);
}

/** Parse Retry-After (seconds or HTTP date) into milliseconds, capped at 30s. */
export function parseRetryAfter(value: string | null, now = Date.now()): number | null {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 30000);
  const at = Date.parse(value);
  if (Number.isNaN(at)) return null;
  return Math.min(Math.max(at - now, 0), 30000);
}

/** Capped exponential backoff with full jitter. `attempt` is 1-based. */
export function backoffDelay(
  attempt: number,
  retryAfterMs: number | null,
  random: () => number = Math.random,
  baseMs = 300,
  capMs = 5000,
): number {
  if (retryAfterMs !== null) return Math.min(retryAfterMs, capMs * 2);
  const ceiling = Math.min(capMs, baseMs * 2 ** (attempt - 1));
  return Math.floor(random() * ceiling);
}

export interface CallOptions {
  adapter: ProviderAdapter;
  apiKey: string;
  baseUrl: string | null;
  model: string;
  messages: ChatMessage[];
  maxAttempts?: number;
  attemptTimeoutMs?: number;
  /** Total budget across attempts, including backoff. */
  deadlineMs?: number;
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
}

export interface CallOutcome {
  result: ProviderResult;
  attempts: number;
  latencyMs: number;
}

export interface FailedCall {
  error: ProviderError;
  attempts: number;
  latencyMs: number;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

async function attemptOnce(opts: CallOptions, timeoutMs: number): Promise<ProviderResult> {
  const { adapter, apiKey, baseUrl, model, messages } = opts;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const req = adapter.build(model, messages, apiKey, baseUrl);
  let res: Response;
  try {
    res = await fetchImpl(req.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...req.headers },
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    const timedOut = error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError');
    throw new ProviderError(timedOut ? 'Provider request timed out.' : 'Could not reach the provider.', {
      retryable: true,
      code: timedOut ? 'timeout' : 'network',
    });
  }
  if (!res.ok) {
    // Drain the body so the connection can be reused; never surface it (may echo the key).
    await res.body?.cancel().catch(() => undefined);
    throw new ProviderError(`Provider returned ${res.status}.`, {
      status: res.status,
      retryable: isRetryableStatus(res.status),
      retryAfterMs: parseRetryAfter(res.headers.get('retry-after')),
      code: res.status === 429 ? 'rate_limited' : res.status >= 500 ? 'provider_unavailable' : 'provider_rejected',
    });
  }
  let data: unknown;
  try {
    data = await res.json();
  } catch {
    throw new ProviderError('Provider returned an invalid response.', { status: res.status, retryable: false, code: 'bad_response' });
  }
  return adapter.parse(data);
}

/** Call a provider with retries. Resolves with the result or a FailedCall — never throws. */
export async function callWithRetry(opts: CallOptions): Promise<CallOutcome | FailedCall> {
  const maxAttempts = Math.max(1, Math.min(opts.maxAttempts ?? 3, 5));
  const attemptTimeout = opts.attemptTimeoutMs ?? 60000;
  const deadline = Date.now() + (opts.deadlineMs ?? 110000);
  const sleep = opts.sleep ?? defaultSleep;
  const started = Date.now();
  let lastError: ProviderError | null = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const remaining = deadline - Date.now();
    if (remaining <= 250) break;
    try {
      const result = await attemptOnce(opts, Math.min(attemptTimeout, remaining));
      return { result, attempts: attempt, latencyMs: Date.now() - started };
    } catch (error) {
      lastError =
        error instanceof ProviderError
          ? error
          : new ProviderError('The AI provider request failed.', { retryable: false, code: 'unknown' });
      if (!lastError.retryable || attempt === maxAttempts) {
        return { error: lastError, attempts: attempt, latencyMs: Date.now() - started };
      }
      const delay = backoffDelay(attempt, lastError.retryAfterMs, opts.random);
      if (Date.now() + delay >= deadline) {
        return { error: lastError, attempts: attempt, latencyMs: Date.now() - started };
      }
      await sleep(delay);
    }
  }
  return {
    error: lastError ?? new ProviderError('Provider deadline exceeded.', { retryable: true, code: 'timeout' }),
    attempts: maxAttempts,
    latencyMs: Date.now() - started,
  };
}

export function isFailedCall(outcome: CallOutcome | FailedCall): outcome is FailedCall {
  return 'error' in outcome;
}
