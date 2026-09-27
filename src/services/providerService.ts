import { getActiveOrganizationId, getSupabase } from '../lib/supabase';

export type AIProviderId = 'openai' | 'anthropic' | 'gemini' | 'custom';

export interface ProviderConnection {
  id: string;
  provider: AIProviderId;
  label: string;
  /** Last 4 characters of the key — the only key material ever returned. */
  key_hint: string;
  status: 'active' | 'revoked';
  updated_at: string;
}

async function invokeFunction<T>(name: 'ai-provider' | 'ai-gateway', body: Record<string, unknown>): Promise<T> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) throw new Error('Sign in to a workspace first.');
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (!session) throw new Error('Your session expired. Sign in again.');
  const { data, error } = await supabase.functions.invoke<T>(name, {
    body: { organization_id: orgId, ...body },
  });
  if (error) {
    // The function returns JSON errors; surface its message when present.
    const message =
      (error as { context?: unknown }).context !== undefined
        ? 'The provider service did not respond. Deploy it: npx supabase functions deploy ' + name
        : error.message;
    throw new Error(message || 'The provider service did not respond.');
  }
  const payload = data as unknown as { error?: string } | null;
  if (payload && typeof payload === 'object' && 'error' in payload && payload.error) {
    throw new Error(payload.error as string);
  }
  return data as T;
}

/** Metadata-only list. Ciphertext is never exposed by the API. */
export async function listProviders(): Promise<ProviderConnection[]> {
  const data = await invokeFunction<{ connections: ProviderConnection[] }>('ai-provider', {
    action: 'list',
  });
  return data.connections ?? [];
}

/**
 * Connect (or rotate) a provider. The API key travels to the edge function
 * over TLS and is encrypted there — it is never stored in the browser, in
 * localStorage, or returned by any API.
 */
export async function connectProvider(input: {
  provider: AIProviderId;
  api_key: string;
  base_url?: string;
  label?: string;
}): Promise<ProviderConnection> {
  const data = await invokeFunction<{ connection: ProviderConnection }>('ai-provider', {
    action: 'connect',
    ...input,
  });
  return data.connection;
}

/** Revoke a connection. Destroys the stored key material server-side. */
export async function revokeProvider(provider: AIProviderId): Promise<void> {
  await invokeFunction<{ revoked: boolean }>('ai-provider', { action: 'revoke', provider });
}

export interface GatewayMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface GatewayResult {
  forwarded: boolean;
  decision: 'allow' | 'block' | 'review';
  text?: string;
  masked?: boolean;
  request_id?: string;
  reasons?: string[];
  detections?: unknown[];
  approval_request_id?: string | null;
  error?: string;
}

/**
 * Send a prompt through the AI gateway: policy evaluation happens first,
 * and the provider is only called when the request is allowed (masked when
 * a mask policy triggers).
 */
export async function gatewayChat(input: {
  provider: AIProviderId;
  model: string;
  messages: GatewayMessage[];
  purpose?: string;
}): Promise<GatewayResult> {
  return invokeFunction<GatewayResult>('ai-gateway', input);
}
