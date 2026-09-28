// supabase/functions/evaluate-ai-request/index.ts
//
// Secure server-side entry point for AI request evaluation.
// - Validates the caller's JWT (Supabase Auth).
// - Validates input; organization membership is enforced inside the
//   evaluate_ai_request Postgres function (it raises 42501 otherwise).
// - The service-role key never leaves the server; the RPC runs with the
//   caller's user context so RLS and auth.uid() keep working.
//
// Deploy: supabase functions deploy evaluate-ai-request
// Secrets: none required (uses the caller's JWT, not the service role key).

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import { detectSensitiveContent, maskSensitiveContent, type ContentFinding } from '../_shared/detect.ts';
import { detectThreats, type ThreatFinding } from '../_shared/threat.ts';
import { checkEndpointRateLimit, rateLimitedResponse } from '../_shared/rateLimit.ts';
import { recordMetric, nowMs } from '../_shared/metrics.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

interface EvaluatePayload {
  organization_id: string;
  ai_model_id: string;
  purpose: string;
  data_asset_ids: string[];
  user_id?: string | null;
  agent_id?: string | null;
  request_type?: string;
  /** Optional free-text content, scanned in-memory for PII/secrets (never stored). */
  content?: string | null;
}

/** Max content size scanned for PII/secrets (DoS guard for the regex scan). */
const MAX_CONTENT_LENGTH = 100_000;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function badRequest(message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 400,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

serve(async (req: Request): Promise<Response> => {
  const t0 = nowMs();
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY');
  if (!supabaseUrl || !supabaseAnonKey) {
    return new Response(JSON.stringify({ error: 'Server misconfigured' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // 1. Authenticate the caller from the Authorization header.
  const authHeader = req.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'Missing authorization' }), {
      status: 401,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const supabase = createClient(supabaseUrl, supabaseAnonKey, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false },
  });

  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError || !user) {
    return new Response(JSON.stringify({ error: 'Invalid or expired session' }), {
      status: 401,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // 2. Validate input (never trust the client).
  let body: EvaluatePayload;
  try {
    body = await req.json();
  } catch {
    return badRequest('Request body must be valid JSON.');
  }

  const {
    organization_id,
    ai_model_id,
    purpose,
    data_asset_ids,
    user_id = null,
    agent_id = null,
    request_type = 'chat',
  } = body;

  if (!organization_id || !UUID_RE.test(organization_id)) return badRequest('organization_id must be a UUID.');
  if (!ai_model_id || !UUID_RE.test(ai_model_id)) return badRequest('ai_model_id must be a UUID.');
  if (!purpose || typeof purpose !== 'string' || purpose.length > 500) {
    return badRequest('purpose is required (max 500 chars).');
  }
  if (!Array.isArray(data_asset_ids) || data_asset_ids.length === 0 || data_asset_ids.length > 50) {
    return badRequest('data_asset_ids must be a non-empty array (max 50).');
  }
  if (!data_asset_ids.every((id) => typeof id === 'string' && UUID_RE.test(id))) {
    return badRequest('Every data_asset_id must be a UUID.');
  }
  if (user_id !== null && (typeof user_id !== 'string' || !UUID_RE.test(user_id))) {
    return badRequest('user_id must be a UUID or null.');
  }
  if (agent_id !== null && (typeof agent_id !== 'string' || !UUID_RE.test(agent_id))) {
    return badRequest('agent_id must be a UUID or null.');
  }
  const allowedTypes = ['chat', 'completion', 'agent_action', 'data_access', 'tool_call'];
  if (!allowedTypes.includes(request_type)) return badRequest('Invalid request_type.');

  // Optional free-text content: scanned in-memory for PII/secrets and attack
  // patterns (never stored or logged). Threat findings travel in the same
  // array so threat.category policy conditions can match them.
  let detections: Array<ContentFinding | ThreatFinding> = [];
  if (body.content !== undefined && body.content !== null) {
    if (typeof body.content !== 'string') return badRequest('content must be a string when provided.');
    if (body.content.length > MAX_CONTENT_LENGTH) {
      return badRequest(`content must be at most ${MAX_CONTENT_LENGTH} characters.`);
    }
    detections = [...detectSensitiveContent(body.content), ...detectThreats(body.content)];
  }

  // Rate limit per organization, scoped by the organization_id in the payload.
  // The RPC is SECURITY DEFINER so this works with the caller's user client;
  // the rate_limit_rules read inside the helper fails RLS by design and the
  // helper falls back to its built-in constants.
  // Fail-open: the helper allows the request if the limiter itself errors.
  const rateLimit = await checkEndpointRateLimit(supabase, 'evaluate-ai-request', organization_id);
  if (!rateLimit.allowed) {
    recordMetric(supabase, {
      functionName: 'evaluate-ai-request',
      organizationId: organization_id,
      status: 'rate_limited',
      latencyMs: nowMs() - t0,
    });
    return rateLimitedResponse(rateLimit.retryAfter, corsHeaders);
  }

  // 3. Run the secure database logic with the caller's identity.
  // Lazy approval expiry (no pg_cron): best-effort sweep before evaluation.
  try {
    await supabase.rpc('expire_stale_approvals');
  } catch {
    /* hygiene only — never fail the request */
  }
  const { data, error } = await supabase.rpc('evaluate_ai_request', {
    p_organization_id: organization_id,
    p_ai_model_id: ai_model_id,
    p_purpose: purpose,
    p_data_asset_ids: data_asset_ids,
    p_user_id: user_id,
    p_agent_id: agent_id,
    p_request_type: request_type,
    p_content_findings: detections,
  });

  if (error) {
    const status = error.code === '42501' ? 403 : 500;
    // Best-effort production metrics (fire-and-forget; never fails the request).
    // 403 not-a-member is a caller error -> recorded as 'ok' with an
    // errorCode so error_rate stays a true function-health signal.
    recordMetric(supabase, {
      functionName: 'evaluate-ai-request',
      organizationId: organization_id,
      status: status === 500 ? 'error' : 'ok',
      latencyMs: nowMs() - t0,
      errorCode: status === 500 ? 'rpc_error' : 'not_member',
    });
    const message =
      error.code === '42501'
        ? 'You are not a member of this organization.'
        : 'Evaluation failed. Please try again.';
    return new Response(JSON.stringify({ error: message }), {
      status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // 4. Structured response — same shape as the frontend simulator expects.
  // When the database says the request was masked, redact the detected
  // sensitive spans here (in-memory only; the raw content is never stored).
  const result = (data ?? {}) as Record<string, unknown>;
  if (result.masked === true && typeof body.content === 'string' && body.content.length > 0) {
    const { masked, maskedCount } = maskSensitiveContent(body.content);
    result.transformed_content = masked;
    result.masked_count = maskedCount;
  }
  recordMetric(supabase, {
    functionName: 'evaluate-ai-request',
    organizationId: organization_id,
    status: 'ok',
    latencyMs: nowMs() - t0,
  });
  return new Response(JSON.stringify(result), {
    status: 200,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
});
