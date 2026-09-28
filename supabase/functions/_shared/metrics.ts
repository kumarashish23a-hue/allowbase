// Shared production-metrics helper for Deno Edge Functions.
// Dependency-free: writes through the `record_function_metric` SECURITY
// DEFINER RPC (migration 022_monitoring.sql), so even user-scoped clients
// (e.g. evaluate-ai-request's anon+JWT client) can record metrics.
//
// Contract with migration 022 (do not change one without the other):
//   public.record_function_metric(p_function_name text,
//     p_organization_id uuid, p_status text, p_latency_ms int,
//     p_error_code text) returns void

export type MetricStatus = 'ok' | 'error' | 'rate_limited';

export interface MetricData {
  functionName: string;
  organizationId?: string | null;
  status: MetricStatus;
  latencyMs: number;
  errorCode?: string | null;
}

interface MetricsRpcClient {
  rpc(
    fn: 'record_function_metric',
    args: {
      p_function_name: string;
      p_organization_id: string | null;
      p_status: string;
      p_latency_ms: number;
      p_error_code: string | null;
    },
  ): PromiseLike<unknown>;
}

/**
 * Record one function invocation. Fire-and-forget: it never throws and never
 * rejects, so a metrics outage can never fail a real request.
 */
export function recordMetric(client: MetricsRpcClient, data: MetricData): void {
  try {
    const pending = client.rpc('record_function_metric', {
      p_function_name: data.functionName,
      p_organization_id: data.organizationId ?? null,
      p_status: data.status,
      p_latency_ms: Math.max(0, Math.round(data.latencyMs)),
      p_error_code: data.errorCode ?? null,
    });
    void Promise.resolve(pending).catch(() => {
      /* metrics are best-effort */
    });
  } catch {
    /* metrics are best-effort */
  }
}

/** Millisecond timestamp for latency measurement: const t0 = nowMs(); ... recordMetric(..., latencyMs: nowMs() - t0). */
export function nowMs(): number {
  return Date.now();
}
