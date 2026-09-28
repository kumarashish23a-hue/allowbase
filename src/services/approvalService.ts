import { getActiveOrganizationId, getSupabase } from '../lib/supabase';

export interface ApprovalItem {
  id: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  note: string | null;
  created_at: string;
  decided_at: string | null;
  expires_at: string | null;
  escalation_level: number;
  escalated_at: string | null;
  assigned_to: string | null;
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

export interface TimelineItem {
  kind: 'event' | 'comment';
  id: string;
  action?: string;
  actor_type?: string;
  actor_name: string | null;
  body?: string;
  note?: string | null;
  metadata?: Record<string, unknown>;
  at: string;
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
  expires_at: string | null;
  escalation_level: number | null;
  escalated_at: string | null;
  assigned_to: string | null;
  ai_requests: ApprovalRequestRow | ApprovalRequestRow[] | null;
}

/** Supabase may return to-one joins as an object or a single-element array. */
function one<T>(value: T | T[] | null | undefined): T | null {
  if (value === null || value === undefined) return null;
  return Array.isArray(value) ? (value[0] ?? null) : value;
}

/**
 * Expire overdue approvals and auto-escalate stale ones for the active org.
 * Runs before listing so the queue is always current, even without pg_cron.
 * Best-effort: a failure here never blocks the list.
 */
async function sweepApprovals(orgId: string): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) return;
  await supabase.rpc('expire_stale_approvals', { p_organization_id: orgId });
}

/** Approval requests for the active organization, newest first. Empty when offline. */
export async function listApprovals(): Promise<ApprovalItem[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  await sweepApprovals(orgId).catch(() => undefined);
  const { data, error } = await supabase
    .from('approval_requests')
    .select(
      'id,status,note,created_at,decided_at,expires_at,escalation_level,escalated_at,assigned_to, ai_requests!inner(id,purpose,status,risk_level,created_at,metadata, ai_models(name))',
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
      expires_at: row.expires_at,
      escalation_level: row.escalation_level ?? 0,
      escalated_at: row.escalated_at,
      assigned_to: row.assigned_to,
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
 * Decide an approval request. Owners/admins, or the delegated security
 * reviewer, may decide — enforced again inside decide_approval.
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

export async function escalateApproval(id: string, note?: string): Promise<number> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.rpc('escalate_approval', {
    p_approval_id: id,
    p_note: note?.trim() ? note.trim() : null,
  });
  if (error) throw new Error(error.message || 'Could not escalate the approval request.');
  return (data as { escalation_level: number }).escalation_level;
}

/** Assign a reviewer (owner/admin/security member), or pass null to unassign. */
export async function delegateApproval(id: string, assignee: string | null): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { error } = await supabase.rpc('delegate_approval', { p_approval_id: id, p_assignee: assignee });
  if (error) throw new Error(error.message || 'Could not delegate the approval request.');
}

export async function addApprovalComment(id: string, body: string): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { error } = await supabase.rpc('add_approval_comment', { p_approval_id: id, p_body: body.trim() });
  if (error) throw new Error(error.message || 'Could not add the comment.');
}

export async function getApprovalTimeline(id: string): Promise<TimelineItem[]> {
  const supabase = getSupabase();
  if (!supabase) return [];
  const { data, error } = await supabase.rpc('get_approval_timeline', { p_approval_id: id });
  if (error) throw new Error('Could not load the approval history.');
  return (data ?? []) as TimelineItem[];
}
