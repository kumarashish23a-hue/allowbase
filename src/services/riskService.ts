import type { RiskEventRow } from '../lib/db';
import { getActiveOrganizationId, getSupabase } from '../lib/supabase';

/** Open risk events for the active organization. Empty when offline. */
export async function getRiskEvents(limit = 20): Promise<RiskEventRow[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const { data, error } = await supabase
    .from('risk_events')
    .select('*')
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw new Error('Could not load risk events.');
  return (data ?? []) as RiskEventRow[];
}

/** Update a risk event's status (triage). */
export async function setRiskEventStatus(id: string, status: string): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { error } = await supabase.from('risk_events').update({ status }).eq('id', id);
  if (error) throw new Error('Could not update the risk event.');
}
