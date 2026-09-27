import type { PolicyRow } from '../lib/db';
import { getActiveOrganizationId, getSupabase } from '../lib/supabase';
import type { Decision, Policy } from '../types';

const effectMap: Record<string, Decision> = {
  allow: 'ALLOW',
  block: 'BLOCK',
  mask: 'MASK',
  redact: 'REDACT',
  review: 'REDACT',
  require_approval: 'REDACT',
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
    status: row.status,
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

export type PolicyAction = 'allow' | 'block' | 'mask' | 'redact' | 'require_approval';
export type PolicyOperator = 'equals' | 'not_equals' | 'in' | 'not_in';

export interface PolicyConditionDraft {
  field: string;
  operator: PolicyOperator;
  value: string | string[] | boolean;
}

export interface PolicyDraft {
  name: string;
  description: string;
  action: PolicyAction;
  /** Lower numbers are evaluated first; the first matching policy wins. */
  priority: number;
  conditions: PolicyConditionDraft[];
}

/** Encode a draft condition value the way the engine's policy_condition_matches expects. */
export function encodeValue(field: string, operator: PolicyOperator, value: string | string[] | boolean): unknown {
  if (operator === 'in' || operator === 'not_in') {
    const arr = Array.isArray(value)
      ? value
      : String(value)
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
    return arr;
  }
  if (field === 'ai.is_external' || field === 'ai.is_approved') {
    return value === true || value === 'true';
  }
  return Array.isArray(value) ? (value[0] ?? '') : value;
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

const actionMap: Record<Decision, PolicyAction> = {
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
  if (!draft.name.trim()) throw new Error('Give the policy a name.');
  // Empty conditions are allowed (matches every request) — the Admin
  // quick-create uses this; the builder modal requires at least one.
  const priority = Number.isFinite(draft.priority) ? Math.max(0, Math.floor(draft.priority)) : 100;
  const { data, error } = await supabase
    .from('policies')
    .insert({
      organization_id: orgId,
      name: draft.name.trim(),
      description: draft.description.trim() || null,
      status: 'active',
      priority,
      rule: {
        conditions: draft.conditions.map((condition) => ({
          field: condition.field,
          operator: condition.operator,
          value: encodeValue(condition.field, condition.operator, condition.value),
        })),
      },
      action: draft.action,
    })
    .select('*')
    .single();
  if (error) throw new Error('Could not create the policy.');
  return toPolicy(data as PolicyRow);
}

/** Map a UI Decision to the database action vocabulary (for legacy callers). */
export function decisionToAction(decision: Decision): PolicyAction {
  return actionMap[decision];
}

/** Pause or re-activate a policy. A paused policy is skipped by the engine. */
export async function setPolicyStatus(policyId: string, status: 'active' | 'paused'): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { error } = await supabase.from('policies').update({ status }).eq('id', policyId);
  if (error) throw new Error('Could not update the policy. Only owners, admins, or security can do this.');
}

/** Permanently delete a policy. Cannot be undone. */
export async function deletePolicy(policyId: string): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { error } = await supabase.from('policies').delete().eq('id', policyId);
  if (error) throw new Error('Could not delete the policy. Only owners or admins can do this.');
}
