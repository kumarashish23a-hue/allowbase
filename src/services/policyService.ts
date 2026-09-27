import type { PolicyRow } from '../lib/db';
import { getActiveOrganizationId, getSupabase } from '../lib/supabase';
import type { Decision, Policy } from '../types';

const effectMap: Record<string, Decision> = {
  allow: 'ALLOW',
  block: 'BLOCK',
  mask: 'MASK',
  redact: 'REDACT',
  review: 'REDACT',
};

function conditionValue(value: unknown): string {
  if (Array.isArray(value)) return value.join(', ');
  if (value === null || value === undefined) return '';
  return String(value);
}

export function toPolicy(row: PolicyRow): Policy {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? '',
    conditions: (row.rule?.conditions ?? []).map((condition) => ({
      field: condition.field,
      operator: condition.operator,
      value: conditionValue(condition.value),
    })),
    action: row.description ?? row.action,
    effect: effectMap[row.action] ?? 'REDACT',
    updated: new Date(row.updated_at).toLocaleDateString(),
  };
}

export interface PolicyDraft {
  name: string;
  description: string;
  effect: Decision;
  conditions: { field: string; operator: string; value: string }[];
}

/** Policies for the active organization; mock list when offline. */
export async function listPolicies(): Promise<Policy[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const { data, error } = await supabase
    .from('policies')
    .select('*')
    .eq('organization_id', orgId)
    .order('priority', { ascending: true });
  if (error) throw new Error('Could not load policies.');
  return (data as PolicyRow[]).map(toPolicy);
}

const actionMap: Record<Decision, string> = {
  ALLOW: 'allow',
  BLOCK: 'block',
  MASK: 'mask',
  REDACT: 'redact',
};

/** Create a policy in Supabase. Only used when configured. */
export async function createPolicy(draft: PolicyDraft): Promise<Policy> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase
    .from('policies')
    .insert({
      organization_id: orgId,
      name: draft.name,
      description: draft.description,
      status: 'active',
      priority: 100,
      rule: {
        conditions: draft.conditions.map((condition) => ({
          field: condition.field,
          operator: condition.operator,
          value: condition.value,
        })),
      },
      action: actionMap[draft.effect],
    })
    .select('*')
    .single();
  if (error) throw new Error('Could not create the policy.');
  return toPolicy(data as PolicyRow);
}
