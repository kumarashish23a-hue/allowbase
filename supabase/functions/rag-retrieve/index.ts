// supabase/functions/rag-retrieve/index.ts
//
// Phase E — RAG retrieval API.
//
// Answers "what does the corpus know about X?" for an authorized caller:
//   1. Authenticate: Supabase user session (JWT) + org membership (any
//      active role may retrieve; what they SEE is governed by the ACL).
//      Phase E is JWT-only; machine-key access is a documented follow-up.
//   2. Resolve the caller's clearance from their org role and embed the
//      query with the explicitly configured embedding_model (no silent
//      default; the org's provider connection must exist).
//   3. Fetch candidates via the SQL RPC rag_search_candidates, which
//      filters by tenant, clearance (capped at the role-derived maximum),
//      and grants BEFORE any similarity is computed. Similarity NEVER sees
//      unfiltered rows.
//   4. Rank the filtered candidates by cosine similarity in the function
//      and return the top_k chunks.
//   5. Audit: action 'rag_retrieve' with counts only — chunk content never
//      lands in audit logs.
//
// Never retrieve based on semantic similarity alone: a chunk the caller is
// not authorized to read cannot appear in the results, no matter how
// similar it is to the query.

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import type { SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import {
  embedTexts,
  rankBySimilarity,
  roleMaxClearance,
  RAG_VERSION,
  type RankCandidate,
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
const MAX_QUERY_CHARS = 4000;
const MAX_TOP_K = 20;
const MAX_CANDIDATES = 2000;

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
  if (typeof body.query !== 'string' || body.query.trim().length === 0 || body.query.length > MAX_QUERY_CHARS) {
    return `query must be non-empty and at most ${MAX_QUERY_CHARS} chars.`;
  }
  if (body.provider !== undefined && !(EMBEDDING_PROVIDERS as readonly string[]).includes(String(body.provider))) {
    return 'provider must be one of: openai, custom.';
  }
  if (typeof body.embedding_model !== 'string' || body.embedding_model.trim().length === 0 || body.embedding_model.length > 120) {
    return 'embedding_model is required (max 120 chars) — configure it explicitly, there is no silent default.';
  }
  if (body.top_k !== undefined && (typeof body.top_k !== 'number' || body.top_k < 1 || body.top_k > MAX_TOP_K)) {
    return `top_k must be between 1 and ${MAX_TOP_K}.`;
  }
  if (
    body.candidate_limit !== undefined &&
    (typeof body.candidate_limit !== 'number' || body.candidate_limit < 1 || body.candidate_limit > MAX_CANDIDATES)
  ) {
    return `candidate_limit must be between 1 and ${MAX_CANDIDATES}.`;
  }
  return null;
}

interface CandidateRow extends RankCandidate {
  chunk_id: string;
  document_id: string;
  chunk_index: number;
  content: string;
  embedding_model: string | null;
  classification: string;
  title: string;
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

  // 1. Authenticate: JWT + active membership (any role may retrieve).
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

  const { data: role, error: roleError } = await userClient.rpc('org_role', { org_id: organization_id });
  if (roleError || !role) return json({ error: 'Not a member of this organization.' }, 403);
  const clearance = roleMaxClearance(role as string);

  const meter = (status: 'ok' | 'error' | 'rate_limited', errorCode?: string | null) =>
    recordMetric(admin, {
      functionName: 'rag-retrieve',
      organizationId: organization_id,
      status,
      latencyMs: nowMs() - t0,
      errorCode: errorCode ?? null,
    });

  const rateLimit = await checkEndpointRateLimit(admin, 'rag-retrieve', organization_id);
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

  // 3. Embed the query.
  let queryEmbedding: number[];
  try {
    [queryEmbedding] = await embedTexts(
      { baseUrl: storedBase, apiKey, model: embeddingModel },
      [body.query as string],
    );
  } catch {
    meter('error', 'embedding_error');
    return json({ error: 'The embedding provider call failed.' }, 502);
  } finally {
    apiKey = '';
  }

  // 4. Fetch the SECURITY-FILTERED candidates (tenant + clearance + grants).
  //    The RPC caps the requested clearance at the role-derived maximum, so
  //    even a direct RPC call cannot escalate clearance.
  const candidateLimit = (body.candidate_limit as number | undefined) ?? 500;
  const { data: candidates, error: candError } = await userClient.rpc('rag_search_candidates', {
    p_organization_id: organization_id,
    p_clearance: clearance,
    p_limit: candidateLimit,
  });
  if (candError) {
    meter('error', 'candidate_error');
    return json({ error: 'Could not search the corpus.' }, 500);
  }
  const rows = (candidates ?? []) as CandidateRow[];

  // 5. Rank the filtered candidates by cosine similarity — never before.
  const topK = (body.top_k as number | undefined) ?? 5;
  const ranked = rankBySimilarity(queryEmbedding, rows, topK);

  // 6. Audit (counts only — never chunk content).
  try {
    await admin.from('audit_logs').insert({
      organization_id,
      actor_user_id: user.id,
      actor_type: 'user',
      action: 'rag_retrieve',
      resource_type: 'rag_document',
      resource_id: null,
      result: 'allowed',
      metadata: {
        rag_version: RAG_VERSION,
        clearance,
        candidates: rows.length,
        returned: ranked.length,
        embedding_model: embeddingModel,
        provider,
      },
    });
  } catch {
    /* audit is best-effort */
  }

  meter('ok');
  return json({
    results: ranked.map((r) => ({
      chunk_id: r.candidate.chunk_id,
      document_id: r.candidate.document_id,
      chunk_index: r.candidate.chunk_index,
      title: r.candidate.title,
      classification: r.candidate.classification,
      score: r.score,
      content: r.candidate.content,
    })),
    candidates_considered: rows.length,
    clearance,
  });
});
