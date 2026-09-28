// supabase/functions/rag-ingest/index.ts
//
// Phase E — RAG ingestion API.
//
// Ingests a document into the organization's RAG corpus with classification:
//   1. Authenticate: Supabase user session (JWT) + org membership. Only
//      owner/admin/security/developer may ingest. (Phase E is JWT-only;
//      machine-key access is a documented follow-up.)
//   2. Validate: title, content (<= 200 KB), classification.
//   3. Load the org's embedding provider connection (openai or an
//      OpenAI-compatible custom provider; SSRF-checked like the gateway)
//      and decrypt the key. embedding_model is REQUIRED — there is no
//      silent default; the caller configures it explicitly.
//   4. Chunk deterministically (shared rag.ts) and embed each chunk.
//   5. Store the document + chunks. Writes go through the caller's JWT
//      client so RLS applies; the audit row is written service-role.
//   6. Audit: action 'rag_ingest' with counts only — document content and
//      embeddings never land in audit logs.

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import type { SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import {
  chunkText,
  embedTexts,
  clearanceRank,
  RAG_VERSION,
  type Clearance,
} from '../_shared/rag.ts';
import { checkEndpointRateLimit, rateLimitedResponse } from '../_shared/rateLimit.ts';
import { recordMetric, nowMs } from '../_shared/metrics.ts';
import { decryptSecret } from '../_shared/providerCrypto.ts';
import { isSafeProviderUrlAsync } from '../_shared/ssrf.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-api-key',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMBEDDING_PROVIDERS = ['openai', 'custom'] as const;
const MAX_CONTENT_CHARS = 200 * 1024;
const MAX_CHUNKS = 500;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

function validate(body: Record<string, unknown>): string | null {
  if (typeof body.organization_id !== 'string' || !UUID_RE.test(body.organization_id)) {
    return 'organization_id must be a UUID.';
  }
  if (typeof body.title !== 'string' || body.title.trim().length === 0 || body.title.length > 200) {
    return 'title must be a non-empty string (max 200 chars).';
  }
  if (typeof body.content !== 'string' || body.content.length === 0 || body.content.length > MAX_CONTENT_CHARS) {
    return `content must be non-empty and at most ${MAX_CONTENT_CHARS} chars.`;
  }
  if (body.classification !== undefined && clearanceRank(String(body.classification)) === -1) {
    return 'classification must be one of: public, internal, confidential, restricted.';
  }
  if (body.provider !== undefined && !(EMBEDDING_PROVIDERS as readonly string[]).includes(String(body.provider))) {
    return 'provider must be one of: openai, custom.';
  }
  if (typeof body.embedding_model !== 'string' || body.embedding_model.trim().length === 0 || body.embedding_model.length > 120) {
    return 'embedding_model is required (max 120 chars) — configure it explicitly, there is no silent default.';
  }
  if (body.chunk !== undefined) {
    const c = body.chunk as Record<string, unknown>;
    if (typeof c !== 'object' || c === null) return 'chunk must be an object.';
    if (c.maxChars !== undefined && (typeof c.maxChars !== 'number' || c.maxChars < 64 || c.maxChars > 8000)) {
      return 'chunk.maxChars must be between 64 and 8000.';
    }
    if (c.overlapChars !== undefined && (typeof c.overlapChars !== 'number' || c.overlapChars < 0 || c.overlapChars > 2000)) {
      return 'chunk.overlapChars must be between 0 and 2000.';
    }
  }
  return null;
}

serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);
  const t0 = nowMs();

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) {
    return json({ error: 'Server misconfigured.' }, 500);
  }
  const admin: SupabaseClient = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });

  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400);
  }
  const validationError = validate(body);
  if (validationError) return json({ error: validationError }, 400);

  const organization_id = body.organization_id as string;

  // 1. Authenticate: JWT + ingestion role.
  const authHeader = req.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return json({ error: 'Missing authorization.' }, 401);
  const userClient: SupabaseClient = createClient(supabaseUrl, supabaseAnonKey, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false },
  });
  const {
    data: { user },
    error: userError,
  } = await userClient.auth.getUser();
  if (userError || !user) return json({ error: 'Invalid or expired session.' }, 401);

  const { data: canIngest, error: roleError } = await userClient.rpc('has_org_role', {
    org_id: organization_id,
    allowed: ['owner', 'admin', 'security', 'developer'],
  });
  if (roleError || !canIngest) return json({ error: 'Not authorized to ingest documents.' }, 403);

  const meter = (status: 'ok' | 'error' | 'rate_limited', errorCode?: string | null) =>
    recordMetric(admin, {
      functionName: 'rag-ingest',
      organizationId: organization_id,
      status,
      latencyMs: nowMs() - t0,
      errorCode: errorCode ?? null,
    });

  const rateLimit = await checkEndpointRateLimit(admin, 'rag-ingest', organization_id);
  if (!rateLimit.allowed) {
    meter('rate_limited');
    return rateLimitedResponse(rateLimit.retryAfter, corsHeaders);
  }

  // 2. Load the embedding provider connection and decrypt the key.
  const provider = (body.provider as string | undefined) ?? 'openai';
  const embeddingModel = (body.embedding_model as string).trim();
  const { data: conn, error: connError } = await admin
    .from('ai_provider_connections')
    .select('id,provider,base_url,key_ciphertext,key_iv,status')
    .eq('organization_id', organization_id)
    .eq('provider', provider)
    .eq('status', 'active')
    .maybeSingle();
  if (connError || !conn) {
    meter('ok', 'no_connection');
    return json({ error: `No active ${provider} connection. Connect it first in the console.` }, 400);
  }
  const storedBase = (conn.base_url as string | null) ?? 'https://api.openai.com/v1';
  if (provider === 'custom' && !(await isSafeProviderUrlAsync(storedBase))) {
    meter('ok', 'unsafe_base_url');
    return json({ error: 'The configured provider URL failed the safety check.' }, 400);
  }
  let apiKey: string;
  try {
    apiKey = await decryptSecret(conn.key_ciphertext as string, conn.key_iv as string);
  } catch {
    meter('error', 'decrypt_error');
    return json(
      { error: 'Could not decrypt the stored key. The PROVIDER_ENCRYPTION_KEY secret may have changed — reconnect the provider.' },
      500,
    );
  }

  // 3. Chunk and embed.
  const chunkOpts = (body.chunk as { maxChars?: number; overlapChars?: number } | undefined) ?? {};
  const chunks = chunkText(body.content as string, chunkOpts);
  if (chunks.length > MAX_CHUNKS) {
    meter('ok', 'too_many_chunks');
    return json({ error: `Document produced ${chunks.length} chunks; the limit is ${MAX_CHUNKS}. Raise chunk.maxChars.` }, 400);
  }
  let embeddings: number[][];
  try {
    embeddings = await embedTexts(
      { baseUrl: storedBase, apiKey, model: embeddingModel },
      chunks,
    );
  } catch {
    meter('error', 'embedding_error');
    // Never leak key material or raw provider internals — status only.
    return json({ error: 'The embedding provider call failed.' }, 502);
  } finally {
    apiKey = '';
  }

  // 4. Store the document + chunks through the caller's JWT client (RLS applies).
  const classification = (body.classification as Clearance | undefined) ?? 'internal';
  const { data: doc, error: docError } = await userClient
    .from('rag_documents')
    .insert({
      organization_id,
      title: (body.title as string).trim(),
      classification,
      created_by: user.id,
    })
    .select('id')
    .single();
  if (docError || !doc) {
    meter('error', 'document_insert_failed');
    return json({ error: 'Could not store the document.' }, 500);
  }
  const rows = chunks.map((content, i) => ({
    organization_id,
    document_id: (doc as { id: string }).id,
    chunk_index: i,
    content,
    embedding: embeddings[i],
    embedding_model: embeddingModel,
  }));
  const { error: chunkError } = await userClient.from('rag_chunks').insert(rows);
  if (chunkError) {
    // Roll back the orphaned document rather than leaving a chunkless shell.
    await userClient.from('rag_documents').delete().eq('id', (doc as { id: string }).id);
    meter('error', 'chunk_insert_failed');
    return json({ error: 'Could not store document chunks.' }, 500);
  }

  // 5. Audit (counts only — never content or embeddings).
  try {
    await admin.from('audit_logs').insert({
      organization_id,
      actor_user_id: user.id,
      actor_type: 'user',
      action: 'rag_ingest',
      resource_type: 'rag_document',
      resource_id: (doc as { id: string }).id,
      result: 'allowed',
      metadata: {
        rag_version: RAG_VERSION,
        classification,
        chunks: chunks.length,
        embedding_model: embeddingModel,
        provider,
      },
    });
  } catch {
    /* audit is best-effort */
  }

  meter('ok');
  return json({
    document_id: (doc as { id: string }).id,
    chunks: chunks.length,
    classification,
    embedding_model: embeddingModel,
  });
});
