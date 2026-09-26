import { agents as seedAgents } from '../data/mock';
import type { AgentPermissionRow, AiAgentRow } from '../lib/db';
import { getActiveOrganizationId, getSupabase } from '../lib/supabase';
import type { Agent, RiskLevel } from '../types';

const riskMap: Record<string, RiskLevel> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'High',
};

const statusMap: Record<string, Agent['status']> = {
  active: 'Active',
  paused: 'Paused',
  disabled: 'Paused',
};

interface AgentLookup {
  agents: AiAgentRow[];
  models: Map<string, string>;
  permissions: AgentPermissionRow[];
  assetNames: Map<string, string>;
}

async function loadLookup(supabase: NonNullable<ReturnType<typeof getSupabase>>, orgId: string): Promise<AgentLookup> {
  const [agentsRes, modelsRes, permsRes, assetsRes] = await Promise.all([
    supabase.from('ai_agents').select('*').eq('organization_id', orgId).order('name'),
    supabase.from('ai_models').select('id,name').eq('organization_id', orgId),
    supabase
      .from('ai_agent_data_permissions')
      .select('*, agent:ai_agents!inner(organization_id)')
      .eq('agent.organization_id', orgId),
    supabase.from('data_assets').select('id,name').eq('organization_id', orgId),
  ]);
  if (agentsRes.error) throw new Error('Could not load AI agents.');
  return {
    agents: (agentsRes.data ?? []) as AiAgentRow[],
    models: new Map(((modelsRes.data ?? []) as { id: string; name: string }[]).map((m) => [m.id, m.name])),
    permissions: ((permsRes.data ?? []) as (AgentPermissionRow & { agent: unknown })[]).map(({ agent, ...rest }) => rest),
    assetNames: new Map(((assetsRes.data ?? []) as { id: string; name: string }[]).map((a) => [a.id, a.name])),
  };
}

function toAgent(lookup: AgentLookup, row: AiAgentRow): Agent {
  const allowed = lookup.permissions
    .filter((p) => p.agent_id === row.id && p.permission_type === 'read' && p.data_asset_id)
    .map((p) => lookup.assetNames.get(p.data_asset_id as string) ?? 'Unknown asset');
  return {
    id: row.id,
    name: row.name,
    owner: String(row.metadata?.owner ?? 'Unassigned'),
    model: (row.ai_model_id && lookup.models.get(row.ai_model_id)) || 'Unknown model',
    allowed,
    denied: [],
    risk: riskMap[row.risk_level] ?? 'Medium',
    status: statusMap[row.status] ?? 'Active',
    requests: '—',
  };
}

/** AI agents for the active organization; mock list when offline. */
export async function listAgents(): Promise<Agent[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return seedAgents;
  const lookup = await loadLookup(supabase, orgId);
  return lookup.agents.map((row) => toAgent(lookup, row));
}

/** Pause or resume an agent. Returns the new status label. */
export async function setAgentStatus(id: string, status: 'active' | 'paused'): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { error } = await supabase.from('ai_agents').update({ status }).eq('id', id);
  if (error) throw new Error('Could not update the agent.');
}
