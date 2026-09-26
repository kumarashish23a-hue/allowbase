import type { AuditLogRow } from '../lib/db';
import { getActiveOrganizationId, getSupabase } from '../lib/supabase';

/** Recent audit log entries for the active organization. Empty when offline. */
export async function getAuditLogs(limit = 50): Promise<AuditLogRow[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const { data, error } = await supabase
    .from('audit_logs')
    .select('*')
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw new Error('Could not load audit logs.');
  return (data ?? []) as AuditLogRow[];
}

/** Policy evaluations for one AI request, newest policy order first. */
export async function getEvaluationsForRequest(requestId: string): Promise<
  { policy: string; decision: string; reason: string | null; checks: Record<string, boolean> }[]
> {
  const supabase = getSupabase();
  if (!supabase) return [];
  const { data, error } = await supabase
    .from('policy_evaluations')
    .select('decision,reason,checks,policy:policies(name)')
    .eq('ai_request_id', requestId)
    .order('created_at');
  if (error) throw new Error('Could not load policy evaluations.');
  return (data ?? []).map((row) => ({
    policy: (row.policy as unknown as { name: string } | null)?.name ?? 'Unknown policy',
    decision: row.decision,
    reason: row.reason,
    checks: (row.checks ?? {}) as Record<string, boolean>,
  }));
}
