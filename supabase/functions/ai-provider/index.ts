// supabase/functions/ai-provider/index.ts
//
// Manages AI provider API keys for the AI gateway.
//
// - The provider API key is encrypted (AES-GCM) in this function before it
//   reaches Postgres. Plaintext keys are never stored, logged, or returned.
// - Listing returns metadata only: provider, label, key hint (last 4 chars),
//   status. Ciphertext is never exposed.
// - Connecting / revoking requires an owner, admin, or security role.
//   Reading the connection list requires organization membership.
// - One active connection per provider per organization.
//
// Routes (all POST with an action field — browsers cannot send a GET body):
//   { action: 'list', organization_id }
//       list connections (metadata only — ciphertext is never exposed)
//   { action: 'connect', organization_id, provider, api_key, base_url?, label? }
//       connect or rotate a provider key (owner/admin/security only)
//   { action: 'revoke', organization_id, provider }
//       revoke a connection and destroy its key material (owner/admin/security)
//
// Deploy: supabase functions deploy ai-provider
// Requires secret: supabase secrets set PROVIDER_ENCRYPTION_KEY=$(openssl rand -hex 32)

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import { encryptSecret } from '../_shared/providerCrypto.ts';
import { isSafeProviderUrl } from '../_shared/ssrf.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const PROVIDERS = ['openai', 'anthropic', 'gemini', 'custom'] as const;
type Provider = (typeof PROVIDERS)[number];

const PROVIDER_LABELS: Record<Provider, string> = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
  gemini: 'Google Gemini',
  custom: 'Custom',
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PRIVILEGED_ROLES = ['owner', 'admin', 'security'];
const ALL_ROLES = ['owner', 'admin', 'security', 'developer', 'analyst', 'viewer'];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

function toPublic(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.id,
    provider: row.provider,
    label: row.label,
    key_hint: row.key_hint,
    status: row.status,
    updated_at: row.updated_at,
  };
}

serve(async (req: Request): Promise<Response> => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) {
    return json({ error: 'Server misconfigured.' }, 500);
  }

  // 1. Authenticate the caller from the Authorization header.
  const authHeader = req.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return json({ error: 'Missing authorization.' }, 401);
  const userClient = createClient(supabaseUrl, supabaseAnonKey, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false },
  });
  const {
    data: { user },
    error: userError,
  } = await userClient.auth.getUser();
  if (userError || !user) return json({ error: 'Invalid or expired session.' }, 401);

  // Service-role client for the encrypted credentials table (RLS denies
  // direct access; role checks below gate every operation).
  const admin = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });

  async function requireRole(organization_id: string, allowed: string[]): Promise<Response | null> {
    if (!UUID_RE.test(organization_id)) return json({ error: 'organization_id must be a UUID.' }, 400);
    const { data: ok, error } = await userClient.rpc('has_org_role', {
      org_id: organization_id,
      allowed,
    });
    if (error || !ok) return json({ error: 'Not authorized for this organization.' }, 403);
    return null;
  }

  let body: {
    action?: string;
    organization_id?: string;
    provider?: string;
    api_key?: string;
    base_url?: string | null;
    label?: string | null;
  };
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400);
  }
  const action = body.action ?? '';
  const organization_id = body.organization_id ?? '';

  // ---------------------------------------------------------------- list
  if (action === 'list') {
    const denied = await requireRole(organization_id, ALL_ROLES);
    if (denied) return denied;
    const { data, error } = await admin
      .from('ai_provider_connections')
      .select('id,provider,label,key_hint,status,updated_at')
      .eq('organization_id', organization_id)
      .order('provider');
    if (error) return json({ error: 'Could not load provider connections.' }, 500);
    return json({ connections: (data ?? []).map(toPublic) });
  }

  // ---------------------------------------------------------------- connect / rotate
  if (action === 'connect') {
    const { provider = '', api_key = '' } = body;
    const denied = await requireRole(organization_id, PRIVILEGED_ROLES);
    if (denied) return denied;
    if (!(PROVIDERS as readonly string[]).includes(provider)) {
      return json({ error: `provider must be one of: ${PROVIDERS.join(', ')}.` }, 400);
    }
    if (typeof api_key !== 'string' || api_key.length < 8 || api_key.length > 500) {
      return json({ error: 'api_key is required.' }, 400);
    }
    let base_url: string | null = null;
    if (provider === 'custom') {
      // SSRF: the gateway later fetches this URL with the decrypted provider
      // key attached. Only public https targets — no private, loopback,
      // link-local, or metadata addresses. Re-validated on every gateway call.
      if (typeof body.base_url !== 'string' || !isSafeProviderUrl(body.base_url)) {
        return json(
          { error: 'base_url must be a public https URL. Private, loopback, link-local, and metadata addresses are blocked.' },
          400,
        );
      }
      base_url = body.base_url.replace(/\/$/, '');
    }
    const label =
      typeof body.label === 'string' && body.label.trim().length > 0 && body.label.length <= 80
        ? body.label.trim()
        : PROVIDER_LABELS[provider as Provider];

    let encrypted: { ciphertext: string; iv: string };
    try {
      encrypted = await encryptSecret(api_key);
    } catch {
      return json(
        { error: 'The server is missing its encryption secret. Ask an admin to set PROVIDER_ENCRYPTION_KEY.' },
        500,
      );
    }

    const { data, error } = await admin
      .from('ai_provider_connections')
      .upsert(
        {
          organization_id,
          provider,
          label,
          base_url,
          key_ciphertext: encrypted.ciphertext,
          key_iv: encrypted.iv,
          key_hint: '••••' + api_key.slice(-4),
          status: 'active',
          created_by: user.id,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'organization_id,provider' },
      )
      .select('id,provider,label,key_hint,status,updated_at')
      .single();
    if (error) return json({ error: 'Could not save the provider connection.' }, 500);
    // The plaintext key is dropped here — it never leaves this scope.
    return json({ connection: toPublic(data as Record<string, unknown>) });
  }

  // ---------------------------------------------------------------- revoke
  if (action === 'revoke') {
    const provider = body.provider ?? '';
    const denied = await requireRole(organization_id, PRIVILEGED_ROLES);
    if (denied) return denied;
    if (!(PROVIDERS as readonly string[]).includes(provider)) {
      return json({ error: `provider must be one of: ${PROVIDERS.join(', ')}.` }, 400);
    }
    // Revoking destroys the key material; the row stays as an audit trail.
    const { error } = await admin
      .from('ai_provider_connections')
      .update({
        status: 'revoked',
        key_ciphertext: '',
        key_iv: '',
        key_hint: '••••revoked',
        updated_at: new Date().toISOString(),
      })
      .eq('organization_id', organization_id)
      .eq('provider', provider);
    if (error) return json({ error: 'Could not revoke the provider connection.' }, 500);
    return json({ revoked: true, provider });
  }

  return json({ error: "action must be one of: list, connect, revoke." }, 400);
});
