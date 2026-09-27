import {
  detectionCategories as mockDetectionCategories,
  metrics as mockMetrics,
  modelUsage as mockModelUsage,
  requestSeries as mockSeries,
  riskDistribution as mockRisk,
  riskyAgents as mockRiskyAgents,
  sourceUsage as mockSourceUsage,
} from '../data/mock';
import { getActiveOrganizationId, getSupabase, isSupabaseConfigured } from '../lib/supabase';
import type { Metric, ModelUsage, RiskSlice, SourceUsage, TimePoint } from '../types';

export interface RiskyAgent {
  agent: string;
  requests: number;
  blocked: number;
}

export interface DetectionCategory {
  category: string;
  hits: number;
}

export interface DashboardData {
  metrics: Metric[];
  series: TimePoint[];
  risk: RiskSlice[];
  modelUsage: ModelUsage[];
  sourceUsage: SourceUsage[];
  riskyAgents: RiskyAgent[];
  detectionCategories: DetectionCategory[];
  /** True when the numbers came from Supabase instead of mock data. */
  live: boolean;
}

type Range = '24h' | '7d' | '30d';

const rangeDays: Record<Range, number> = { '24h': 1, '7d': 7, '30d': 30 };

function formatNumber(value: number): string {
  return value.toLocaleString('en-US');
}

async function loadLive(range: Range): Promise<DashboardData> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) throw new Error('Not connected.');

  const [metricsRes, seriesRes, riskRes, modelsRes, sourcesRes] = await Promise.all([
    supabase.rpc('get_dashboard_metrics', { p_organization_id: orgId }),
    supabase.rpc('get_requests_over_time', { p_organization_id: orgId, p_days: rangeDays[range] }),
    supabase.rpc('get_risk_distribution', { p_organization_id: orgId }),
    supabase.rpc('get_model_usage', { p_organization_id: orgId }),
    supabase.rpc('get_source_usage', { p_organization_id: orgId }),
  ]);
  const firstError = [metricsRes, seriesRes, riskRes, modelsRes, sourcesRes].find((res) => res.error);
  if (firstError?.error) throw new Error(`Could not load dashboard metrics: ${firstError.error.message}`);

  // The 018 aggregates are optional: if the user has not run that migration
  // yet, the panels render empty instead of breaking the whole dashboard.
  const [riskyAgentsRes, detectionsRes] = await Promise.all([
    supabase.rpc('get_risky_agents', { p_organization_id: orgId, p_days: rangeDays[range] }),
    supabase.rpc('get_detection_categories', { p_organization_id: orgId, p_days: rangeDays[range] }),
  ]);
  const riskyAgents: RiskyAgent[] = riskyAgentsRes.error
    ? []
    : (((riskyAgentsRes.data ?? []) as { agent: string; requests: number; blocked: number }[]).map((row) => ({
        agent: row.agent,
        requests: Number(row.requests),
        blocked: Number(row.blocked),
      })) ?? []);
  const detectionCategories: DetectionCategory[] = detectionsRes.error
    ? []
    : (((detectionsRes.data ?? []) as { category: string; hits: number }[]).map((row) => ({
        category: row.category,
        hits: Number(row.hits),
      })) ?? []);

  const m = metricsRes.data as {
    total_requests: number;
    allowed: number;
    blocked: number;
    in_review: number;
    sensitive_events: number;
    active_agents: number;
    high_risk: number;
  };
  const total = m.total_requests || 1;
  const metrics: Metric[] = [
    { label: 'AI Requests', value: formatNumber(m.total_requests), delta: `${range} window`, tone: 'neutral' },
    {
      label: 'Allowed',
      value: formatNumber(m.allowed),
      delta: `${((m.allowed / total) * 100).toFixed(1)}% allow rate`,
      tone: 'good',
    },
    {
      label: 'Blocked',
      value: formatNumber(m.blocked),
      delta: `${((m.blocked / total) * 100).toFixed(1)}% blocked`,
      tone: 'bad',
    },
    { label: 'Sensitive Events', value: formatNumber(m.sensitive_events), delta: 'Open findings', tone: 'warn' },
    { label: 'Active AI Agents', value: formatNumber(m.active_agents), delta: 'Currently active', tone: 'neutral' },
    { label: 'High Risk', value: formatNumber(m.high_risk), delta: 'Open high-severity events', tone: 'warn' },
  ];

  const series: TimePoint[] = ((seriesRes.data ?? []) as { bucket: string; requests: number; blocked: number }[]).map(
    (row) => ({
      label: row.bucket,
      requests: Number(row.requests),
      blocked: Number(row.blocked),
      allowed: Number(row.requests) - Number(row.blocked),
    }),
  );

  const riskTotal =
    ((riskRes.data ?? []) as { name: string; value: number }[]).reduce((sum, row) => sum + Number(row.value), 0) || 1;
  const risk: RiskSlice[] = ((riskRes.data ?? []) as { name: string; value: number }[]).map((row) => ({
    name: row.name,
    value: Math.round((Number(row.value) / riskTotal) * 100),
  }));

  return {
    metrics,
    series,
    risk,
    modelUsage: ((modelsRes.data ?? []) as { model: string; requests: number }[]).map((row) => ({
      model: row.model,
      requests: Number(row.requests),
    })),
    sourceUsage: ((sourcesRes.data ?? []) as { source: string; requests: number }[]).map((row) => ({
      source: row.source,
      requests: Number(row.requests),
    })),
    riskyAgents,
    detectionCategories,
    live: true,
  };
}

/**
 * Dashboard data. Uses Supabase RPC aggregates when the user is signed in with
 * a workspace — backend failures surface as explicit errors, never silent mock
 * data. Signed-out visitors get the simulated landing-page preview.
 */
export async function getDashboard(range: Range): Promise<DashboardData> {
  if (isSupabaseConfigured()) {
    const supabase = getSupabase();
    const {
      data: { session },
    } = await supabase!.auth.getSession();
    const orgId = await getActiveOrganizationId();
    if (session && orgId) {
      return await loadLive(range);
    }
  }
  return {
    metrics: mockMetrics,
    series: mockSeries[range],
    risk: mockRisk,
    modelUsage: mockModelUsage,
    sourceUsage: mockSourceUsage,
    riskyAgents: mockRiskyAgents,
    detectionCategories: mockDetectionCategories,
    live: false,
  };
}
