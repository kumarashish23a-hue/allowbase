import { createClient, type SupabaseClient } from '@supabase/supabase-js';

const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

/** The configured Supabase project URL (public). */
export function getSupabaseUrl(): string | null {
  return url ?? null;
}

/** True when the app is pointed at a real Supabase project. */
export function isSupabaseConfigured(): boolean {
  return Boolean(url && anonKey);
}

let client: SupabaseClient | null = null;

/**
 * Shared Supabase client. Returns null when the app is not configured,
 * in which case services fall back to local mock data.
 * The anon key is safe for browser use; the service-role key is never here.
 */
export function getSupabase(): SupabaseClient | null {
  if (!isSupabaseConfigured()) return null;
  if (!client) {
    client = createClient(url as string, anonKey as string);
  }
  return client;
}

let cachedOrgId: string | null | undefined;

/** First active organization of the signed-in user. Null when signed out. */
export async function getActiveOrganizationId(): Promise<string | null> {
  const supabase = getSupabase();
  if (!supabase) return null;
  const userId = await getLocalUserId();
  if (!userId) {
    return null;
  }
  if (cachedOrgId !== undefined) return cachedOrgId;
  const { data, error } = await supabase
    .from('organization_members')
    .select('organization_id')
    .eq('user_id', userId)
    .eq('status', 'active')
    .order('created_at', { ascending: true })
    .limit(1)
    .maybeSingle();
  const orgId: string | null = error || !data ? null : data.organization_id;
  // Cache only successful resolutions. A transient failure must never poison
  // every later lookup for the rest of the page load.
  if (orgId) cachedOrgId = orgId;
  return orgId;
}

export function clearOrgCache(): void {
  cachedOrgId = undefined;
}

/**
 * Current user id from the local session. Fast and never hits the network —
 * unlike auth.getUser(), which can hang during multi-tab token refresh races.
 * Server-side RLS still validates the token on every query, so this is only
 * ever used to decide what to ask for, never what to allow.
 */
export async function getLocalUserId(): Promise<string | null> {
  const supabase = getSupabase();
  if (!supabase) return null;
  const {
    data: { session },
  } = await supabase.auth.getSession();
  return session?.user?.id ?? null;
}

/** Pin the active organization (e.g. when an admin switches clients). */
export function setActiveOrganizationId(orgId: string | null): void {
  cachedOrgId = orgId ?? undefined;
}
