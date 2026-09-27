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

function requireClient() {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured. Sign in to use the admin panel.');
  return supabase;
}

/** Members of an organization with their profile names. RLS scopes visibility. */
export async function listMembers(orgId: string): Promise<AdminMember[]> {
  const supabase = requireClient();
  const { data, error } = await supabase
    .from('organization_members')
    .select('id,user_id,role,status,created_at,profiles(full_name)')
    .eq('organization_id', orgId)
    .order('created_at', { ascending: true });
  if (error) throw new Error('Could not load members.');
  return (data ?? []).map((row) => ({
    id: row.id as string,
    user_id: row.user_id as string,
    role: row.role as string,
    status: row.status as string,
    full_name: (row.profiles as { full_name?: string | null } | null)?.full_name ?? null,
    created_at: row.created_at as string,
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
