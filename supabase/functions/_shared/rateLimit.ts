// Shared fixed-window rate limiter for Deno Edge Functions.
// Dependency-free: talks to Postgres only through the `check_rate_limit`
// SECURITY DEFINER RPC (migration 020_rate_limits.sql), so it works with any
// client (anon+JWT, service role, API-key client).
//
// Contract with migration 020 (do not change one without the other):
//   public.check_rate_limit(p_bucket text, p_max int, p_window_seconds int)
//     returns jsonb {"allowed": bool, "retry_after_seconds": int,
//                    "limit": int, "count": int}

export type RateLimitedEndpoint = 'ingest-event' | 'evaluate-ai-request' | 'ai-gateway' | 'rag-ingest' | 'rag-retrieve';

export interface RateLimitDecision {
  allowed: boolean;
  /** Seconds the caller should wait before retrying (0 when allowed). */
  retryAfter: number;
  limit: number;
  count: number;
}

import type { SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';

/** Tunable defaults when the rate_limit_rules row is missing/unreadable. */
const FALLBACK_LIMITS: Record<RateLimitedEndpoint, { max: number; windowSeconds: number }> = {
  'ingest-event': { max: 600, windowSeconds: 60 },
  'evaluate-ai-request': { max: 300, windowSeconds: 60 },
  'ai-gateway': { max: 120, windowSeconds: 60 },
  'rag-ingest': { max: 60, windowSeconds: 60 },
  'rag-retrieve': { max: 120, windowSeconds: 60 },
};

/**
 * Check the rate limit for one endpoint+scope bucket.
 * `scopeKey` identifies the bucket: API key id for ingest-event,
 * organization id for evaluate-ai-request and ai-gateway.
 * Fail-open: if the limiter itself errors, the request is allowed (rate
 * limiting is a protective control, not the auth boundary) and the caller
 * should still record a metric.
 */
export async function checkEndpointRateLimit(
  client: SupabaseClient,
  endpoint: RateLimitedEndpoint,
  scopeKey: string,
): Promise<RateLimitDecision> {
  const fallback = FALLBACK_LIMITS[endpoint];
  let max = fallback.max;
  let windowSeconds = fallback.windowSeconds;
  try {
    const { data, error } = await client
      .from('rate_limit_rules')
      .select('max_requests, window_seconds')
      .eq('endpoint', endpoint)
      .maybeSingle();
    if (!error && data && data.max_requests > 0 && data.window_seconds > 0) {
      max = data.max_requests;
      windowSeconds = data.window_seconds;
    }
  } catch {
    // RLS or network issue reading rules -> fall back to constants.
  }

  const bucket = `rl:${endpoint}:${scopeKey}`;
  try {
    const { data, error } = await client.rpc('check_rate_limit', {
      p_bucket: bucket,
      p_max: max,
      p_window_seconds: windowSeconds,
    });
    if (error || !data) return { allowed: true, retryAfter: 0, limit: max, count: 0 };
    return {
      allowed: data.allowed === true,
      retryAfter: Math.max(0, data.retry_after_seconds ?? 0),
      limit: data.limit ?? max,
      count: data.count ?? 0,
    };
  } catch {
    return { allowed: true, retryAfter: 0, limit: max, count: 0 };
  }
}

/** Standard 429 response for an exceeded limit. */
export function rateLimitedResponse(retryAfter: number, corsHeaders: Record<string, string>): Response {
  return new Response(JSON.stringify({ error: 'rate_limited', message: 'Rate limit exceeded. Try again later.' }), {
    status: 429,
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      'Retry-After': String(Math.max(1, retryAfter)),
    },
  });
}
