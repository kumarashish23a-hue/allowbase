// Shared request plumbing for edge functions: client IP extraction, rate-limit
// checks, and fire-and-forget metrics. Metrics never block or fail a request.

// deno-lint-ignore no-explicit-any
type AdminClient = any;

/** Best-effort client IP. Supabase's edge sits behind a proxy that sets x-forwarded-for. */
export function clientIp(req: Request): string | null {
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    const first = forwarded.split(',')[0]?.trim();
    if (first) return first;
  }
  return req.headers.get('cf-connecting-ip') ?? req.headers.get('x-real-ip') ?? null;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: string;
}

/**
 * Fixed-window rate limit via the check_rate_limit RPC. Fails OPEN on
 * infrastructure errors so a metrics/DB hiccup never takes the gateway down;
 * policy enforcement still runs afterwards.
 */
export async function checkRateLimit(
  admin: AdminClient,
  bucket: string,
  limit: number,
  windowSeconds = 60,
): Promise<RateLimitResult> {
  const { data, error } = await admin.rpc('check_rate_limit', {
    p_bucket: bucket,
    p_limit: limit,
    p_window_seconds: windowSeconds,
  });
  if (error || !data) {
    console.error('check_rate_limit failed; allowing request');
    return { allowed: true, limit, remaining: limit, resetAt: new Date(Date.now() + windowSeconds * 1000).toISOString() };
  }
  const r = data as { allowed: boolean; limit: number; remaining: number; reset_at: string };
  return { allowed: r.allowed, limit: r.limit, remaining: r.remaining, resetAt: r.reset_at };
}

export function rateLimitHeaders(r: RateLimitResult): Record<string, string> {
  const resetSeconds = Math.max(0, Math.ceil((Date.parse(r.resetAt) - Date.now()) / 1000));
  return {
    'X-RateLimit-Limit': String(r.limit),
    'X-RateLimit-Remaining': String(r.remaining),
    'X-RateLimit-Reset': String(resetSeconds),
    ...(r.allowed ? {} : { 'Retry-After': String(resetSeconds || 1) }),
  };
}

export interface MetricRow {
  organization_id: string;
  ai_request_id?: string | null;
  source: 'gateway' | 'ingest';
  provider?: string | null;
  model?: string | null;
  outcome: 'allowed' | 'blocked' | 'review' | 'error' | 'rate_limited' | 'denied';
  status_code: number;
  latency_ms: number;
  provider_latency_ms?: number | null;
  attempts?: number;
  fallback_used?: boolean;
  input_tokens?: number | null;
  output_tokens?: number | null;
  cost_usd?: number | null;
  error_code?: string | null;
  output_findings?: unknown[];
}

export async function recordMetric(admin: AdminClient, row: MetricRow): Promise<void> {
  try {
    const { error } = await admin.from('request_metrics').insert(row);
    if (error) console.error('request_metrics insert failed:', error.message);
  } catch {
    console.error('request_metrics insert threw');
  }
}
