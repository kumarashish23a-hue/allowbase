import { getActiveOrganizationId, getSupabase } from '../lib/supabase';

export interface ApiKeyItem {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface CreatedApiKey {
  id: string;
  key: string;
  prefix: string;
}

/** Key metadata for the active organization. Plaintext keys are never stored. */
export async function listApiKeys(): Promise<ApiKeyItem[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const { data, error } = await supabase
    .from('api_keys')
    .select('id,name,key_prefix,scopes,expires_at,revoked_at,last_used_at,created_at')
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false });
  if (error) throw new Error('Could not load API keys.');
  return (data ?? []) as ApiKeyItem[];
}

interface CreateKeyResult {
  id: string;
  key: string;
  prefix: string;
}

/**
 * Mint a key. The plaintext is returned ONCE — the caller must show it to the
 * user immediately; it can never be retrieved again.
 */
export async function createApiKey(
  name: string,
  expiresAt: string | null,
  scopes: string[] = ['ingest'],
): Promise<CreatedApiKey> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) throw new Error('Sign in to create an API key.');
  if (scopes.length === 0) throw new Error('Pick at least one scope for the key.');
  const { data, error } = await supabase.rpc('create_api_key', {
    p_organization_id: orgId,
    p_name: name.trim(),
    p_scopes: scopes,
    p_expires_at: expiresAt,
  });
  if (error) {
    if (/owner or admin/i.test(error.message)) {
      throw new Error('Only organization owners and admins can create API keys.');
    }
    throw new Error(error.message || 'Could not create the API key.');
  }
  return data as CreateKeyResult;
}

export async function revokeApiKey(id: string): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Sign in to revoke an API key.');
  const { error } = await supabase.rpc('revoke_api_key', { p_key_id: id });
  if (error) throw new Error(error.message || 'Could not revoke the API key.');
}

/** Ingest endpoint URL for the connected Supabase project. */
export function getIngestEndpoint(): string | null {
  const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
  if (!url) return null;
  return `${url.replace(/\/$/, '')}/functions/v1/ingest-event`;
}

/** AI gateway endpoint URL for the connected Supabase project. */
export function getGatewayEndpoint(): string | null {
  const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
  if (!url) return null;
  return `${url.replace(/\/$/, '')}/functions/v1/ai-gateway`;
}
