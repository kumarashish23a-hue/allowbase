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

interface VerifyRpcClient {
  rpc(
    fn: 'verify_api_key',
    args: { p_key_hash: string; p_scope: string },
  ): Promise<{ data: { key_id: string; organization_id: string } | null; error: unknown }>;
}

/**
 * Verify a key hash for one scope via the verify_api_key RPC.
 * Returns the key identity on success, null when the key is missing,
 * revoked, expired, or lacks the scope. Never throws for caller errors —
 * only for unexpected transport failures (callers should treat those as
 * 500s, not 401s).
 */
export async function verifyApiKeyForScope(
  client: VerifyRpcClient,
  keyHash: string,
  scope: 'ingest' | 'gateway',
): Promise<VerifiedApiKey | null> {
  const { data, error } = await client.rpc('verify_api_key', {
    p_key_hash: keyHash,
    p_scope: scope,
  });
  if (error || !data) return null;
  return { keyId: data.key_id, organizationId: data.organization_id };
}
