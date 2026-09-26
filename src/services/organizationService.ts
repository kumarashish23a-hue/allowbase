import type { OrganizationRow } from '../lib/db';
import { clearOrgCache, getActiveOrganizationId, getSupabase } from '../lib/supabase';

/** Organizations the signed-in user belongs to. Empty when signed out. */
export async function getMyOrganizations(): Promise<OrganizationRow[]> {
  const supabase = getSupabase();
  if (!supabase) return [];
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return [];
  const { data, error } = await supabase
    .from('organization_members')
    .select('organization:organizations(*)')
    .eq('user_id', user.id)
    .eq('status', 'active');
  if (error) throw new Error('Could not load organizations.');
  return (data ?? []).map((row) => row.organization as unknown as OrganizationRow);
}

/** Create an organization and become its owner (server-side RPC). */
export async function createOrganization(name: string): Promise<string> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.rpc('create_organization', { p_name: name });
  if (error) throw new Error('Could not create the organization.');
  clearOrgCache();
  return data as string;
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
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return null;
  const { data, error } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', user.id)
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
