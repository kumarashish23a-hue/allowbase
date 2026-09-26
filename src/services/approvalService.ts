import { getActiveOrganizationId, getSupabase } from '../lib/supabase';

export interface ApprovalItem {
  id: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  note: string | null;
  created_at: string;
  decided_at: string | null;
  request: {
    id: string;
    purpose: string;
    status: string;
    risk_level: string;
    created_at: string;
    model: string | null;
    policies: string[];
  };
}

interface ApprovalRequestRow {
  id: string;
  purpose: string;
  status: string;
  risk_level: string;
  created_at: string;
  metadata: { policies_triggered?: string[] } | null;
  ai_models: { name: string } | { name: string }[] | null;
}

interface ApprovalRow {
  id: string;
  status: ApprovalItem['status'];
  note: string | null;
  created_at: string;
  decided_at: string | null;
  ai_requests: ApprovalRequestRow | ApprovalRequestRow[] | null;
}

/** Supabase may return to-one joins as an object or a single-element array. */
function one<T>(value: T | T[] | null | undefined): T | null {
  if (value === null || value === undefined) return null;
  return Array.isArray(value) ? (value[0] ?? null) : value;
}

/** Approval requests for the active organization, newest first. Empty when offline. */
export async function listApprovals(): Promise<ApprovalItem[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const { data, error } = await supabase
    .from('approval_requests')
    .select(
      'id,status,note,created_at,decided_at, ai_requests!inner(id,purpose,status,risk_level,created_at,metadata, ai_models(name))',
    )
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) throw new Error('Could not load approval requests.');
  return ((data ?? []) as ApprovalRow[]).map((row) => {
    const request = one(row.ai_requests);
    return {
      id: row.id,
      status: row.status,
      note: row.note,
      created_at: row.created_at,
      decided_at: row.decided_at,
      request: {
        id: request?.id ?? '',
        purpose: request?.purpose ?? '',
        status: request?.status ?? '',
        risk_level: request?.risk_level ?? 'low',
        created_at: request?.created_at ?? row.created_at,
        model: one(request?.ai_models)?.name ?? null,
        policies: request?.metadata?.policies_triggered ?? [],
      },
    };
  });
}

/**
 * Decide an approval request. Only organization owners/admins may decide —
 * enforced again inside the decide_approval Postgres function.
 */
export async function decideApproval(
  id: string,
  decision: 'approved' | 'rejected',
  note?: string,
): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { error } = await supabase.rpc('decide_approval', {
    p_approval_id: id,
    p_decision: decision,
    p_note: note?.trim() ? note.trim() : null,
  });
  if (error) throw new Error(error.message || 'Could not decide the approval request.');
}
