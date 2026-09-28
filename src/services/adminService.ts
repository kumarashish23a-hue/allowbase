import { clearOrgCache, getLocalUserId, getSupabase, setActiveOrganizationId } from '../lib/supabase';
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
  /** Monotonically increasing version; every meaningful edit leaves a snapshot. */
  version: number;
  created_at: string;
}

export const MEMBER_ROLES = ['owner', 'admin', 'security', 'developer', 'analyst', 'viewer'] as const;

/** Workspace + role for the /admin access gate. One query, resilient to transient hangs. */
export interface GateMembership {
  role: string;
  organization_id: string;
}

async function withRetry<T>(fn: () => Promise<T>, attempts = 3): Promise<T> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (attempt < attempts - 1) await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
    }
  }
  throw lastError instanceof Error ? lastError : new Error('Could not reach the database.');
}

/**
 * The caller's first active membership. Retries hung requests (aborted after
 * 8s) up to 3 times before throwing. Uses a plain select — no embeds.
 */
export async function getGateMembership(userId: string): Promise<GateMembership | null> {
  const supabase = requireClient();
  return withRetry(async () => {
    const { data, error } = await supabase
      .from('organization_members')
      .select('role, organization_id')
      .eq('user_id', userId)
      .eq('status', 'active')
      .order('created_at', { ascending: true })
      .limit(1)
      .abortSignal(AbortSignal.timeout(8000))
      .maybeSingle();
    if (error) throw error;
    return (data ?? null) as GateMembership | null;
  });
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

/**
 * Permanently delete a client workspace and everything in it. RLS allows
 * only owners. If it was the active client, switches to another workspace.
 */
export async function deleteOrganization(orgId: string): Promise<void> {
  const supabase = requireClient();
  const { error } = await supabase.from('organizations').delete().eq('id', orgId);
  if (error) throw new Error('Could not delete the client. Only owners can delete a workspace.');
  clearOrgCache();
}

/** Add a member to an organization by their user ID. RLS: owner/admin. */
export async function addMember(orgId: string, userId: string, role: string): Promise<void> {
  const supabase = requireClient();
  const trimmed = userId.trim();
  if (!trimmed) throw new Error('User ID cannot be empty.');
  const { error } = await supabase.from('organization_members').insert({
    organization_id: orgId,
    user_id: trimmed,
    role,
    status: 'active',
  });
  if (error) {
    if (/duplicate|unique/i.test(error.message)) {
      throw new Error('That user is already a member.');
    }
    throw new Error('Could not add the member. Check the user ID and try again.');
  }
}

/** Policies of the active organization with status, for admin management. */
export async function listAdminPolicies(orgId: string): Promise<AdminPolicy[]> {
  const supabase = requireClient();
  const { data, error } = await supabase
    .from('policies')
    .select('id,name,description,status,priority,action,version,created_at')
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

/**
 * Remotely sign out a member: stamps force_logout_at on their membership and
 * writes an audit row. Their app watches the flag and signs them out (on
 * load, every minute, and on window focus). App-level enforcement only — the
 * member's API token stays valid until it expires, and they can sign back
 * in afterwards unless also removed.
 */
export async function forceLogoutMember(
  orgId: string,
  memberId: string,
  targetUserId: string,
): Promise<void> {
  const supabase = requireClient();
  const { error } = await supabase
    .from('organization_members')
    .update({ force_logout_at: new Date().toISOString() })
    .eq('id', memberId);
  if (error) {
    if (/force_logout_at/.test(error.message)) {
      throw new Error(
        'Database update needed: run supabase/migrations/014_force_logout.sql once in the Supabase SQL editor.',
      );
    }
    throw new Error('Could not sign out the member.');
  }
  // Audit it. Best-effort: a failed audit row must not undo the sign-out.
  const callerId = await getLocalUserId().catch(() => null);
  const { error: auditError } = await supabase.from('audit_logs').insert({
    organization_id: orgId,
    actor_user_id: callerId,
    actor_type: 'user',
    action: 'member.force_logout',
    resource_type: 'organization_member',
    resource_id: memberId,
    result: 'success',
    metadata: { target_user_id: targetUserId },
  });
  if (auditError) {
    console.warn('[admin] force-logout audit insert failed:', auditError.message);
  }
}
