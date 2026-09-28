// Shared machine-API-key helpers for Deno Edge Functions.
//
// AllowBase API keys (dcp_live_...) authenticate an *organization* for
// machine-to-machine calls. Scopes gate which endpoint a key may use:
//   'ingest'  -> ingest-event
//   'gateway' -> ai-gateway
//
// Verification itself lives in the public.verify_api_key RPC (migration 023):
// hash-only lookup, revoked/expired/scope checks, last_used_at touch. The RPC
// raises 'invalid api key' (errcode 28000) on any failure so callers can map
// it to HTTP 401 without leaking which check failed.

export interface VerifiedApiKey {
  keyId: string;
  organizationId: string;
}

/** SHA-256 hex digest (matches the hash stored by create_api_key). */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Pull an API key out of the request: the x-api-key header, or an
 * Authorization: Bearer <key> where the token looks like one of ours.
 * (JWTs never start with dcp_, so the two never collide.)
 * Returns '' when no key-shaped credential is present.
 */
export function extractApiKey(req: Request): string {
  let apiKey = req.headers.get('x-api-key')?.trim() ?? '';
  const authHeader = req.headers.get('Authorization') ?? '';
  if (!apiKey && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice('Bearer '.length).trim();
    if (token.startsWith('dcp_')) apiKey = token;
  }
  if (!apiKey.startsWith('dcp_live_') || apiKey.length < 20 || apiKey.length > 200) {
    return '';
  }
  return apiKey;
}

import type { SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';

export type ApiKeyVerification =
  | { ok: true; key: VerifiedApiKey }
  | { ok: false; status: 401 | 500 };

/**
 * Verify a key hash for one scope via the verify_api_key RPC.
 *
 * - ok: the key is valid for the scope.
 * - 401: the key is missing, revoked, expired, or lacks the scope
 *   (the RPC raises errcode 28000 / 'invalid api key').
 * - 500: anything else — the RPC itself failed (DB down, permissions).
 *   Mapping transport failures to 401 would disguise an outage as bad keys.
 */
export async function verifyApiKeyForScope(
  client: SupabaseClient,
  keyHash: string,
  scope: 'ingest' | 'gateway',
): Promise<ApiKeyVerification> {
  let data: { key_id: string; organization_id: string } | null;
  let error: { code?: string; message?: string } | null;
  try {
    ({ data, error } = await client.rpc('verify_api_key', {
      p_key_hash: keyHash,
      p_scope: scope,
    }));
  } catch {
    return { ok: false, status: 500 };
  }
  if (!error && data) {
    return { ok: true, key: { keyId: data.key_id, organizationId: data.organization_id } };
  }
  const code = error?.code ?? '';
  const message = error?.message ?? '';
  if (code === '28000' || /invalid api key/i.test(message)) {
    return { ok: false, status: 401 };
  }
  return { ok: false, status: 500 };
}
