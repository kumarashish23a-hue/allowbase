import type { OrganizationRow } from '../lib/db';
import { clearOrgCache, getActiveOrganizationId, getLocalUserId, getSupabase } from '../lib/supabase';

/** Organizations the signed-in user belongs to. Empty when signed out. */
export async function getMyOrganizations(): Promise<OrganizationRow[]> {
  const supabase = getSupabase();
  if (!supabase) return [];
  const userId = await getLocalUserId();
  if (!userId) return [];
  const { data, error } = await supabase
    .from('organization_members')
    .select('organization:organizations(*)')
    .eq('user_id', userId)
    .eq('status', 'active');
  if (error) throw new Error('Could not load organizations.');
  return (data ?? []).map((row) => row.organization as unknown as OrganizationRow);
}

/** Create an organization and become its owner (server-side RPC). */
export async function createOrganization(name: string): Promise<string> {
  const trimmedName = name.trim();
  if (!trimmedName) throw new Error('Organization name is required.');
  if (trimmedName.length > 120) throw new Error('Organization name must be 120 characters or fewer.');
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.rpc('create_organization', { p_name: trimmedName });
  if (error) throw new Error('Could not create the organization.');
  clearOrgCache();
  return data as string;
}

export interface PendingOnboarding {
  email: string;
  fullName: string;
  jobTitle: string;
  department: string;
  organizationName: string;
  industry: string;
}

const PENDING_ONBOARDING_KEY = 'allowbase.pending-onboarding';

/** Store only non-secret onboarding fields while email confirmation is pending. */
export function savePendingOnboarding(draft: PendingOnboarding): void {
  try {
    window.localStorage.setItem(PENDING_ONBOARDING_KEY, JSON.stringify(draft));
  } catch {
    // Private browsing/storage-disabled environments can still finish setup manually.
  }
}

export function getPendingOnboarding(email: string): PendingOnboarding | null {
  try {
    const raw = window.localStorage.getItem(PENDING_ONBOARDING_KEY);
    if (!raw) return null;
    const draft = JSON.parse(raw) as Partial<PendingOnboarding>;
    if (draft.email?.trim().toLowerCase() !== email.trim().toLowerCase()) return null;
    if (!draft.organizationName?.trim()) return null;
    return {
      email: draft.email.trim(),
      fullName: draft.fullName?.trim() ?? '',
      jobTitle: draft.jobTitle?.trim() ?? '',
      department: draft.department?.trim() ?? '',
      organizationName: draft.organizationName.trim(),
      industry: draft.industry?.trim() ?? '',
    };
  } catch {
    return null;
  }
}

export function clearPendingOnboarding(): void {
  try {
    window.localStorage.removeItem(PENDING_ONBOARDING_KEY);
  } catch {
    /* storage is optional */
  }
}

/** Apply the signed-up user's profile and create their first workspace once authenticated. */
export async function completeOnboarding(draft: PendingOnboarding): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) throw new Error('Your session expired. Sign in again.');

  const { error: profileError } = await supabase
    .from('profiles')
    .update({
      full_name: draft.fullName || null,
      job_title: draft.jobTitle || null,
      department: draft.department || null,
    })
    .eq('id', user.id);
  if (profileError) throw new Error('Could not save your profile details.');

  let organization = await getActiveOrganization();
  if (!organization) {
    const organizationId = await createOrganization(draft.organizationName);
    if (draft.industry) await setOrgIndustry(organizationId, draft.industry);
  } else if (draft.industry) {
    await setOrgIndustry(organization.id, draft.industry);
  }
  clearPendingOnboarding();
}

/** Convenience: the organization the app should scope queries to. */
export async function getActiveOrganization(): Promise<OrganizationRow | null> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return null;
  const { data, error } = await supabase.from('organizations').select('*').eq('id', orgId).maybeSingle();
  if (error) throw new Error('Could not load the organization.');
  return data as OrganizationRow | null;
}

/** Role of the signed-in user inside an organization. Null when signed out. */
export async function getMyOrganizationRole(orgId: string): Promise<string | null> {
  const supabase = getSupabase();
  if (!supabase) return null;
  const userId = await getLocalUserId();
  if (!userId) return null;
  const { data, error } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .eq('status', 'active')
    .maybeSingle();
  if (error) throw new Error('Could not load your role.');
  return (data?.role as string | undefined) ?? null;
}

/** Number of active members in an organization. */
export async function getOrganizationMemberCount(orgId: string): Promise<number> {
  const supabase = getSupabase();
  if (!supabase) return 0;
  const { count, error } = await supabase
    .from('organization_members')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId)
    .eq('status', 'active');
  if (error) throw new Error('Could not count members.');
  return count ?? 0;
}

/** Workspace enforcement mode. monitor = detect and log only; enforce = apply policy decisions. */
export type EnforcementMode = 'monitor' | 'enforce';

/** Read a workspace's enforcement mode. Defaults to monitor when unknown. */
export async function getEnforcementMode(orgId: string): Promise<EnforcementMode> {
  const supabase = getSupabase();
  if (!supabase) return 'monitor';
  const { data, error } = await supabase
    .from('organizations')
    .select('enforcement_mode')
    .eq('id', orgId)
    .maybeSingle();
  if (error) throw new Error('Could not load the security mode.');
  return (data?.enforcement_mode as EnforcementMode | undefined) ?? 'monitor';
}

/**
 * Save the workspace's industry label inside organizations.settings.
 * Owner/admin only (enforced by RLS). Never throws for missing settings.
 */
export async function setOrgIndustry(orgId: string, industry: string): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data: current } = await supabase
    .from('organizations')
    .select('settings')
    .eq('id', orgId)
    .maybeSingle();
  const next = { ...((current?.settings ?? {}) as Record<string, unknown>), industry: industry.trim() };
  const { error } = await supabase.from('organizations').update({ settings: next }).eq('id', orgId);
  if (error) throw new Error('Could not save the industry.');
}

/**
 * Set a workspace's enforcement mode. Owner/admin only (enforced by RLS).
 * Switching to monitor never deletes data; switching back to enforce
 * immediately applies policy decisions again.
 */
export async function setEnforcementMode(orgId: string, mode: EnforcementMode): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  if (mode !== 'monitor' && mode !== 'enforce') throw new Error('Invalid security mode.');
  const { error } = await supabase.from('organizations').update({ enforcement_mode: mode }).eq('id', orgId);
  if (error) throw new Error('Could not change the security mode.');
}
