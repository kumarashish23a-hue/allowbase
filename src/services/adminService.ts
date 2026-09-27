import { clearOrgCache, getSupabase, setActiveOrganizationId } from '../lib/supabase';
import { createOrganization } from './organizationService';

export interface AdminMember {
  id: string;
  user_id: string;
  role: string;
  status: string;
  full_name: string | null;
  created_at: string;
}

export interface AdminPolicy {
  id: string;
  name: string;
  description: string | null;
  status: string;
  priority: number;
  action: string;
  created_at: string;
}

export const MEMBER_ROLES = ['owner', 'admin', 'security', 'developer', 'analyst', 'viewer'] as const;

/** Workspace + role for the /admin access gate. One query, resilient to transient hangs. */
export interface GateMembership {
  role: string;
  organization: { id: string; name: string; slug: string } | null;
}

/**
 * The caller's first active membership with its organization. Retries hung
 * requests (aborted after 8s) up to 3 times before throwing.
 */
export async function getGateMembership(userId: string): Promise<GateMembership | null> {
  const supabase = requireClient();
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const { data, error } = await supabase
        .from('organization_members')
        .select('role, organizations(id, name, slug)')
        .eq('user_id', userId)
        .eq('status', 'active')
        .order('created_at', { ascending: true })
        .limit(1)
        .abortSignal(AbortSignal.timeout(8000))
        .maybeSingle();
      if (error) throw error;
      return (data ?? null) as GateMembership | null;
    } catch (err) {
      lastError = err;
      if (attempt < 2) await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
    }
  }
  throw lastError instanceof Error ? lastError : new Error('Could not reach the database.');
}

export interface MemberStats {
  /** Registered active members in the organization. */
  total: number;
  /** Distinct users with audit-log activity in the last 24h. Null when unreadable. */
  activeLast24h: number | null;
}

/** Member counts: total registered + recently active (audit-log based). */
export async function getMemberStats(orgId: string): Promise<MemberStats> {
  const supabase = requireClient();
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const [membersRes, auditRes] = await Promise.all([
    supabase
      .from('organization_members')
      .select('id', { count: 'exact', head: true })
      .eq('organization_id', orgId)
      .eq('status', 'active'),
    supabase
      .from('audit_logs')
      .select('actor_user_id')
      .eq('organization_id', orgId)
      .gte('created_at', since)
      .not('actor_user_id', 'is', null),
  ]);
  if (membersRes.error) throw new Error('Could not load member stats.');
  const activeLast24h = auditRes.error
    ? null
    : new Set((auditRes.data ?? []).map((row) => row.actor_user_id as string)).size;
  return { total: membersRes.count ?? 0, activeLast24h };
}

function requireClient() {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured. Sign in to use the admin panel.');
  return supabase;
}

/** Members of an organization with their profile names. RLS scopes visibility. */
export async function listMembers(orgId: string): Promise<AdminMember[]> {
  const supabase = requireClient();
  // No FK exists between organization_members and profiles, so this is two
  // queries: member rows first (members_select_member allows org members to
  // read them), then names (needs 013_admin_member_reads.sql for non-own rows).
  const { data: memberRows, error } = await supabase
    .from('organization_members')
    .select('id,user_id,role,status,created_at')
    .eq('organization_id', orgId)
    .order('created_at', { ascending: true });
  if (error) throw new Error('Could not load members.');
  const rows = (memberRows ?? []) as {
    id: string;
    user_id: string;
    role: string;
    status: string;
    created_at: string;
  }[];
  const names: Record<string, string | null> = {};
  if (rows.length > 0) {
    const { data: profileRows } = await supabase
      .from('profiles')
      .select('id,full_name')
      .in(
        'id',
        rows.map((row) => row.user_id),
      );
    for (const profile of (profileRows ?? []) as { id: string; full_name: string | null }[]) {
      names[profile.id] = profile.full_name;
    }
  }
  return rows.map((row) => ({
    id: row.id,
    user_id: row.user_id,
    role: row.role,
    status: row.status,
    full_name: names[row.user_id] ?? null,
    created_at: row.created_at,
  }));
}

/** Change a member's role. RLS + the ownership RPC rules enforce permission. */
export async function setMemberRole(memberId: string, role: string): Promise<void> {
  const supabase = requireClient();
  const { error } = await supabase.from('organization_members').update({ role }).eq('id', memberId);
  if (error) throw new Error('Could not change the role. Only owners and admins can do this.');
}

/** Remove a member from the organization. */
export async function removeMember(memberId: string): Promise<void> {
  const supabase = requireClient();
  const { error } = await supabase.from('organization_members').delete().eq('id', memberId);
  if (error) throw new Error('Could not remove the member.');
}

/** Rename a client organization. */
export async function renameOrganization(orgId: string, name: string): Promise<void> {
  const supabase = requireClient();
  const trimmed = name.trim();
  if (!trimmed) throw new Error('Name cannot be empty.');
  const { error } = await supabase.from('organizations').update({ name: trimmed }).eq('id', orgId);
  if (error) throw new Error('Could not rename the organization.');
  clearOrgCache();
}

/** Switch the active client. Takes effect immediately across the app. */
export function switchOrganization(orgId: string): void {
  setActiveOrganizationId(orgId);
}

/** Add a client: creates the organization and makes you its owner. */
export async function addClient(name: string): Promise<string> {
  const id = await createOrganization(name);
  setActiveOrganizationId(id);
  return id;
}

/** Policies of the active organization with status, for admin management. */
export async function listAdminPolicies(orgId: string): Promise<AdminPolicy[]> {
  const supabase = requireClient();
  const { data, error } = await supabase
    .from('policies')
    .select('id,name,description,status,priority,action,created_at')
    .eq('organization_id', orgId)
    .order('priority', { ascending: true });
  if (error) throw new Error('Could not load policies.');
  return (data ?? []) as AdminPolicy[];
}

/** Activate or pause a policy. */
export async function setPolicyStatus(policyId: string, status: 'active' | 'paused'): Promise<void> {
  const supabase = requireClient();
  const { error } = await supabase.from('policies').update({ status }).eq('id', policyId);
  if (error) throw new Error('Could not update the policy.');
}

/** Permanently delete a policy. */
export async function deletePolicy(policyId: string): Promise<void> {
  const supabase = requireClient();
  const { error } = await supabase.from('policies').delete().eq('id', policyId);
  if (error) throw new Error('Could not delete the policy.');
}
