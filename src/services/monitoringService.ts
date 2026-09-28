import { getActiveOrganizationId, getSupabase } from '../lib/supabase';

export interface MonitoringAlert {
  severity: 'critical' | 'warning' | 'info';
  code: string;
  message: string;
}

export interface MonitoringSummary {
  window_hours: number;
  totals: {
    requests: number;
    allowed: number;
    blocked: number;
    review: number;
    errors: number;
    rate_limited: number;
    denied: number;
    fallbacks: number;
    output_redactions: number;
    input_tokens: number;
    output_tokens: number;
    cost_usd: number;
  };
  latency: { p50: number | null; p95: number | null; p99: number | null; provider_p95: number | null };
  error_rate: number;
  denial_rate: number;
  timeseries: { bucket: string; requests: number; errors: number; blocked: number; rate_limited: number; p95_ms: number }[];
  providers: { provider: string; requests: number; errors: number; p95_ms: number; cost_usd: number }[];
  alerts: MonitoringAlert[];
}

/** Latency, error, denial, cost and alert summary for the active organization. */
export async function getMonitoringSummary(hours: number): Promise<MonitoringSummary | null> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return null;
  const { data, error } = await supabase.rpc('get_monitoring_summary', {
    p_organization_id: orgId,
    p_hours: hours,
  });
  if (error) {
    if (/could not find the function|does not exist/i.test(error.message)) {
      throw new Error('Monitoring needs migration 020_production_hardening.sql applied to your database.');
    }
    throw new Error('Could not load monitoring data.');
  }
  const s = data as MonitoringSummary;
  // numeric columns come back as strings from PostgREST jsonb in some setups.
  const n = (v: unknown) => Number(v ?? 0);
  return {
    ...s,
    totals: Object.fromEntries(Object.entries(s.totals).map(([k, v]) => [k, n(v)])) as MonitoringSummary['totals'],
    providers: s.providers.map((p) => ({ ...p, cost_usd: n(p.cost_usd) })),
  };
}
