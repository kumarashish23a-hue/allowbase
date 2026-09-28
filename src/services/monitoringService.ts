import { getSupabase } from '../lib/supabase';

export type MetricStatus = 'ok' | 'error' | 'rate_limited';
export type AlertMetric = 'error_rate' | 'p95_latency_ms' | 'denial_rate' | 'provider_failures';
export type AlertSeverity = 'info' | 'warning' | 'critical';
export type AlertStatus = 'firing' | 'resolved';

export interface FunctionMetric {
  id: string;
  function_name: string;
  organization_id: string | null;
  status: MetricStatus;
  latency_ms: number;
  error_code: string | null;
  created_at: string;
}

export interface AlertRule {
  id: string;
  organization_id: string;
  name: string;
  metric: AlertMetric;
  threshold: number;
  window_minutes: number;
  is_active: boolean;
  created_at: string;
}

export interface Alert {
  id: string;
  rule_id: string;
  organization_id: string;
  message: string;
  severity: AlertSeverity;
  status: AlertStatus;
  fired_at: string;
  resolved_at: string | null;
}

export interface NewAlertRule {
  name: string;
  metric: AlertMetric;
  threshold: number;
  window_minutes: number;
}

export interface MetricSummary {
  total: number;
  errors: number;
  rateLimited: number;
  errorRate: number;
  denialRate: number;
  p95LatencyMs: number;
  providerFailures: number;
}

function client() {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Not connected.');
  return supabase;
}

/** Raw invocation metrics for the last 24h, newest first (capped at 2000 rows). */
export async function getMetrics24h(organizationId: string): Promise<FunctionMetric[]> {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const { data, error } = await client()
    .from('function_metrics')
    .select('*')
    .eq('organization_id', organizationId)
    .gte('created_at', since)
    .order('created_at', { ascending: false })
    .limit(2000);
  if (error) throw new Error(`Could not load metrics: ${error.message}`);
  return (data ?? []) as FunctionMetric[];
}

/** Most recent alerts for the workspace (50). */
export async function getAlerts(organizationId: string): Promise<Alert[]> {
  const { data, error } = await client()
    .from('alerts')
    .select('*')
    .eq('organization_id', organizationId)
    .order('fired_at', { ascending: false })
    .limit(50);
  if (error) throw new Error(`Could not load alerts: ${error.message}`);
  return (data ?? []) as Alert[];
}

/** Alert rules for the workspace. */
export async function getAlertRules(organizationId: string): Promise<AlertRule[]> {
  const { data, error } = await client()
    .from('alert_rules')
    .select('*')
    .eq('organization_id', organizationId)
    .order('created_at', { ascending: false });
  if (error) throw new Error(`Could not load alert rules: ${error.message}`);
  return (data ?? []) as AlertRule[];
}

/** Create an alert rule. RLS restricts this to owners/admins. */
export async function createAlertRule(organizationId: string, rule: NewAlertRule): Promise<AlertRule> {
  const { data, error } = await client()
    .from('alert_rules')
    .insert({
      organization_id: organizationId,
      name: rule.name.trim(),
      metric: rule.metric,
      threshold: rule.threshold,
      window_minutes: rule.window_minutes,
      is_active: true,
    })
    .select('*')
    .single();
  if (error) throw new Error(`Could not create alert rule: ${error.message}`);
  return data as AlertRule;
}

/** Enable or disable an alert rule. RLS restricts this to owners/admins. */
export async function toggleAlertRule(ruleId: string, isActive: boolean): Promise<void> {
  const { error } = await client().from('alert_rules').update({ is_active: isActive }).eq('id', ruleId);
  if (error) throw new Error(`Could not update alert rule: ${error.message}`);
}

/**
 * Summarize raw metrics client-side for the overview cards.
 * p95 uses the nearest-rank method over the observed latencies.
 */
export function summarizeMetrics(rows: FunctionMetric[]): MetricSummary {
  const total = rows.length;
  const errors = rows.filter((r) => r.status === 'error').length;
  const rateLimited = rows.filter((r) => r.status === 'rate_limited').length;
  const latencies = rows.map((r) => r.latency_ms).sort((a, b) => a - b);
  const p95LatencyMs = latencies.length === 0 ? 0 : latencies[Math.max(0, Math.ceil(0.95 * latencies.length) - 1)];
  const providerFailures = rows.filter(
    (r) => r.function_name === 'ai-gateway' && r.status === 'error',
  ).length;
  return {
    total,
    errors,
    rateLimited,
    errorRate: total === 0 ? 0 : errors / total,
    denialRate: total === 0 ? 0 : rateLimited / total,
    p95LatencyMs,
    providerFailures,
  };
}

export const ALERT_METRIC_LABELS: Record<AlertMetric, string> = {
  error_rate: 'Error rate',
  p95_latency_ms: 'P95 latency (ms)',
  denial_rate: 'Rate-limit denial rate',
  provider_failures: 'AI provider failures',
};
