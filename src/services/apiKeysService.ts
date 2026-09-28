import { getActiveOrganizationId, getSupabase } from '../lib/supabase';

export type ApiKeyScope = 'ingest' | 'ingest:content';

export const API_KEY_SCOPES: { id: ApiKeyScope; label: string; description: string; required?: boolean }[] = [
  { id: 'ingest', label: 'ingest', description: 'Ask for policy decisions.', required: true },
  {
    id: 'ingest:content',
    label: 'ingest:content',
    description: 'Send raw prompt text for PII/secret scanning.',
  },
];

export interface ApiKeyItem {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  expires_at: string | null;
  revoked_at: string | null;
  revoked_reason: string | null;
  last_used_at: string | null;
  last_used_ip: string | null;
  use_count: number;
  allowed_cidrs: string[];
  rate_limit_per_minute: number;
  rotated_from: string | null;
  created_at: string;
}

export interface CreatedApiKey {
  id: string;
  key: string;
  prefix: string;
  grace_hours?: number;
}

export interface ApiKeyOptions {
  name: string;
  expiresAt: string | null;
  scopes: ApiKeyScope[];
  allowedCidrs: string[];
  rateLimitPerMinute: number;
}

const SELECT =
  'id,name,key_prefix,scopes,expires_at,revoked_at,revoked_reason,last_used_at,last_used_ip,use_count,allowed_cidrs,rate_limit_per_minute,rotated_from,created_at';

function friendly(message: string | undefined, fallback: string): string {
  if (!message) return fallback;
  if (/owner or admin/i.test(message)) return 'Only organization owners and admins can manage API keys.';
  if (/invalid input syntax for type cidr|invalid cidr/i.test(message)) {
    return 'One of the IP ranges is not valid. Use addresses like 203.0.113.7 or ranges like 10.0.0.0/8.';
  }
  return message;
}

/** Parse a free-text list of IPs/CIDRs (comma, space or newline separated). */
export function parseCidrList(input: string): { values: string[]; invalid: string[] } {
  const entries = input
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?$/;
  const ipv6 = /^[0-9a-f:]+(?:\/(?:12[0-8]|1[01]\d|[1-9]?\d))?$/i;
  const invalid = entries.filter((e) => !(ipv4.test(e) || (e.includes(':') && ipv6.test(e))));
  return { values: [...new Set(entries)], invalid };
}

/** Key metadata for the active organization. Plaintext keys are never stored. */
export async function listApiKeys(): Promise<ApiKeyItem[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const { data, error } = await supabase
    .from('api_keys')
    .select(SELECT)
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false });
  if (error) throw new Error('Could not load API keys.');
  return ((data ?? []) as ApiKeyItem[]).map((k) => ({
    ...k,
    allowed_cidrs: k.allowed_cidrs ?? [],
    use_count: Number(k.use_count ?? 0),
  }));
}

/**
 * Mint a key. The plaintext is returned ONCE — the caller must show it to the
 * user immediately; it can never be retrieved again.
 */
export async function createApiKey(options: ApiKeyOptions): Promise<CreatedApiKey> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) throw new Error('Sign in to create an API key.');
  const { data, error } = await supabase.rpc('create_api_key', {
    p_organization_id: orgId,
    p_name: options.name.trim(),
    p_scopes: options.scopes,
    p_expires_at: options.expiresAt,
    p_allowed_cidrs: options.allowedCidrs,
    p_rate_limit_per_minute: options.rateLimitPerMinute,
  });
  if (error) throw new Error(friendly(error.message, 'Could not create the API key.'));
  return data as CreatedApiKey;
}

/** Replace a key; the old one keeps working for `graceHours` (0 = revoke now). */
export async function rotateApiKey(id: string, graceHours: number): Promise<CreatedApiKey> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Sign in to rotate an API key.');
  const { data, error } = await supabase.rpc('rotate_api_key', { p_key_id: id, p_grace_hours: graceHours });
  if (error) throw new Error(friendly(error.message, 'Could not rotate the API key.'));
  return data as CreatedApiKey;
}

export async function updateApiKeySettings(
  id: string,
  settings: Pick<ApiKeyOptions, 'scopes' | 'allowedCidrs' | 'rateLimitPerMinute'>,
): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Sign in to update an API key.');
  const { error } = await supabase.rpc('update_api_key_settings', {
    p_key_id: id,
    p_scopes: settings.scopes,
    p_allowed_cidrs: settings.allowedCidrs,
    p_rate_limit_per_minute: settings.rateLimitPerMinute,
  });
  if (error) throw new Error(friendly(error.message, 'Could not update the API key.'));
}

export async function revokeApiKey(id: string, reason?: string): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) throw new Error('Sign in to revoke an API key.');
  const { error } = await supabase.rpc('revoke_api_key', {
    p_key_id: id,
    p_reason: reason?.trim() ? reason.trim() : null,
  });
  if (error) throw new Error(friendly(error.message, 'Could not revoke the API key.'));
}

/** Emergency: revoke every live key in the organization. Returns the count. */
export async function revokeAllApiKeys(reason: string): Promise<number> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) throw new Error('Sign in to revoke API keys.');
  const { data, error } = await supabase.rpc('revoke_all_api_keys', {
    p_organization_id: orgId,
    p_reason: reason.trim(),
  });
  if (error) throw new Error(friendly(error.message, 'Could not revoke the API keys.'));
  return (data as { revoked_count: number }).revoked_count;
}

/** Ingest endpoint URL for the connected Supabase project. */
export function getIngestEndpoint(): string | null {
  const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
  if (!url) return null;
  return `${url.replace(/\/$/, '')}/functions/v1/ingest-event`;
}
