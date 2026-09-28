// supabase/functions/ai-gateway/index.ts
//
// The Data Control Plane AI gateway: the enforcement point in front of real
// AI providers.
//
// Every request goes through the full pipeline, server-side:
//   1. Authenticate the caller (Supabase Auth) and check org membership.
//   2. Rate limit per user per organization (fixed window, 60/min default).
//   3. Scan the prompt for secrets/PII (in memory; raw content is never stored).
//   4. For each candidate (primary, then optional fallbacks):
//        a. Load the provider connection and decrypt the key (in memory only).
//        b. Evaluate policies for THAT model — a fallback can never bypass policy.
//        c. Block / hold-for-approval / allow (masking first when required).
//        d. Call the provider with retries + backoff; on a retryable failure
//           after retries, move on to the next candidate.
//   5. Scan the provider's OUTPUT and redact high/critical findings before
//      returning it.
//   6. Record latency, tokens, estimated cost and outcome in request_metrics.
//
// POST { organization_id, provider, model, messages, purpose?,
//        data_asset_ids?, agent_id?, fallbacks?: [{ provider, model }] }
//
// Deploy: supabase functions deploy ai-gateway
// Requires: ai-provider deployed + connected, PROVIDER_ENCRYPTION_KEY secret.
// Optional: GATEWAY_RATE_LIMIT_PER_MINUTE (default 60).

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import {
  detectSensitiveContent,
  maskSensitiveContent,
  type ContentFinding,
} from '../_shared/detect.ts';
import { decryptSecret } from '../_shared/providerCrypto.ts';
import {
  ADAPTERS,
  PROVIDER_IDS,
  callWithRetry,
  isFailedCall,
  type ChatMessage,
  type ProviderId,
} from '../_shared/providers.ts';
import { estimateCostUsd } from '../_shared/pricing.ts';
import {
  checkRateLimit,
  rateLimitHeaders,
  recordMetric,
  type MetricRow,
} from '../_shared/requestContext.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Expose-Headers': 'x-ratelimit-limit, x-ratelimit-remaining, x-ratelimit-reset, retry-after',
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_MESSAGES = 50;
const MAX_MESSAGE_CHARS = 50000;
const MAX_FALLBACKS = 3;
const TOTAL_DEADLINE_MS = 110000;

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json', ...extra },
  });
}

interface Candidate {
  provider: ProviderId;
  model: string;
}

function validModel(model: unknown): model is string {
  return typeof model === 'string' && model.length > 0 && model.length <= 120;
}

function validate(body: Record<string, unknown>): string | null {
  if (!body.organization_id || typeof body.organization_id !== 'string' || !UUID_RE.test(body.organization_id)) {
    return 'organization_id must be a UUID.';
  }
  if (typeof body.provider !== 'string' || !(PROVIDER_IDS as readonly string[]).includes(body.provider)) {
    return `provider must be one of: ${PROVIDER_IDS.join(', ')}.`;
  }
  if (!validModel(body.model)) return 'model is required (max 120 chars).';
  if (!Array.isArray(body.messages) || body.messages.length === 0 || body.messages.length > MAX_MESSAGES) {
    return `messages must be a non-empty array (max ${MAX_MESSAGES}).`;
  }
  for (const m of body.messages as unknown[]) {
    const msg = m as Partial<ChatMessage>;
    if (!msg || !['user', 'assistant', 'system'].includes(msg.role ?? '')) {
      return 'each message needs a role of user, assistant, or system.';
    }
    if (typeof msg.content !== 'string' || msg.content.length === 0 || msg.content.length > MAX_MESSAGE_CHARS) {
      return 'each message needs text content within the size limit.';
    }
  }
  if (body.purpose !== undefined && (typeof body.purpose !== 'string' || body.purpose.length > 500)) {
    return 'purpose must be a string (max 500 chars).';
  }
  if (body.data_asset_ids !== undefined) {
    if (
      !Array.isArray(body.data_asset_ids) ||
      body.data_asset_ids.length > 200 ||
      !(body.data_asset_ids as unknown[]).every((id) => typeof id === 'string' && UUID_RE.test(id))
    ) {
      return 'data_asset_ids must be an array of at most 200 UUIDs.';
    }
  }
  if (body.agent_id !== undefined && body.agent_id !== null && (typeof body.agent_id !== 'string' || !UUID_RE.test(body.agent_id))) {
    return 'agent_id must be a UUID or null.';
  }
  if (body.fallbacks !== undefined) {
    if (!Array.isArray(body.fallbacks) || body.fallbacks.length > MAX_FALLBACKS) {
      return `fallbacks must be an array of at most ${MAX_FALLBACKS} { provider, model } entries.`;
    }
    for (const f of body.fallbacks as unknown[]) {
      const fb = f as Partial<Candidate>;
      if (!fb || typeof fb.provider !== 'string' || !(PROVIDER_IDS as readonly string[]).includes(fb.provider) || !validModel(fb.model)) {
        return 'each fallback needs a valid provider and model.';
      }
    }
  }
  return null;
}

/** Severe output findings are redacted before the answer leaves the gateway. */
function shouldRedactOutput(findings: ContentFinding[], maskPolicy: boolean): boolean {
  if (findings.length === 0) return false;
  return maskPolicy || findings.some((f) => f.severity === 'high' || f.severity === 'critical');
}

serve(async (req: Request): Promise<Response> => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);

  const started = Date.now();
  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) {
    return json({ error: 'Server misconfigured.' }, 500);
  }
  const perMinute = Math.max(1, Math.min(Number(Deno.env.get('GATEWAY_RATE_LIMIT_PER_MINUTE') ?? 60) || 60, 10000));

  // 1. Authenticate the caller.
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

  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400);
  }
  const validationError = validate(body);
  if (validationError) return json({ error: validationError }, 400);

  const organization_id = body.organization_id as string;
  const primary: Candidate = { provider: body.provider as ProviderId, model: body.model as string };
  const fallbacks = ((body.fallbacks as Candidate[] | undefined) ?? []).filter(
    (f) => !(f.provider === primary.provider && f.model === primary.model),
  );
  const candidates: Candidate[] = [primary, ...fallbacks];
  const messages = body.messages as ChatMessage[];
  const purpose = typeof body.purpose === 'string' && body.purpose.length > 0 ? body.purpose : `AI gateway: ${primary.model}`;
  const data_asset_ids = (body.data_asset_ids as string[] | undefined) ?? [];
  const agent_id = (body.agent_id as string | null | undefined) ?? null;

  const { data: isMember, error: memberError } = await userClient.rpc('has_org_role', {
    org_id: organization_id,
    allowed: ['owner', 'admin', 'security', 'developer', 'analyst', 'viewer'],
  });
  if (memberError || !isMember) return json({ error: 'Not a member of this organization.' }, 403);

  const admin = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });

  const metric = (row: Omit<MetricRow, 'organization_id' | 'source' | 'latency_ms'>) =>
    recordMetric(admin, { organization_id, source: 'gateway', latency_ms: Date.now() - started, ...row });

  // 2. Rate limit per user per organization.
  const limit = await checkRateLimit(admin, `gw:${organization_id}:${user.id}`, perMinute, 60);
  const limitHeaders = rateLimitHeaders(limit);
  if (!limit.allowed) {
    await metric({ provider: primary.provider, model: primary.model, outcome: 'rate_limited', status_code: 429, error_code: 'rate_limited' });
    return json({ error: 'Rate limit exceeded. Slow down and retry after the reset.', retry_after_seconds: Number(limitHeaders['Retry-After']) }, 429, limitHeaders);
  }

  // 3. Scan the prompt (in memory; raw content is never stored).
  const detections = detectSensitiveContent(messages.map((m) => m.content).join('\n'));

  let fallbackUsed = false;
  let totalAttempts = 0;
  let lastFailure: { code: string; status: number | null; message: string; request_id: string } | null = null;
  const tried: { provider: string; model: string; error: string }[] = [];

  for (let index = 0; index < candidates.length; index++) {
    const candidate = candidates[index];
    const isFallback = index > 0;
    const remainingBudget = TOTAL_DEADLINE_MS - (Date.now() - started);
    if (remainingBudget < 2000) break;

    // 4a. Load the provider connection.
    const { data: conn } = await admin
      .from('ai_provider_connections')
      .select('id,provider,label,base_url,key_ciphertext,key_iv,status')
      .eq('organization_id', organization_id)
      .eq('provider', candidate.provider)
      .eq('status', 'active')
      .maybeSingle();
    if (!conn) {
      if (!isFallback) {
        return json({ error: `No active ${candidate.provider} connection. Connect it first in the console.` }, 400, limitHeaders);
      }
      tried.push({ provider: candidate.provider, model: candidate.model, error: 'not_connected' });
      continue;
    }

    // Register the model if new (external, unapproved by default).
    let modelId: string | null = null;
    const { data: existingModel } = await admin
      .from('ai_models')
      .select('id')
      .eq('organization_id', organization_id)
      .eq('provider', conn.label)
      .eq('name', candidate.model)
      .maybeSingle();
    if (existingModel) {
      modelId = (existingModel as { id: string }).id;
    } else {
      const { data: created, error: modelError } = await admin
        .from('ai_models')
        .insert({
          organization_id,
          name: candidate.model,
          provider: conn.label,
          model_identifier: candidate.model,
          model_type: 'chat',
          is_external: true,
          is_approved: false,
          risk_level: 'medium',
          metadata: { registered_by: 'ai-gateway' },
        })
        .select('id')
        .single();
      if (modelError || !created) return json({ error: 'Could not register the AI model.' }, 500, limitHeaders);
      modelId = (created as { id: string }).id;
    }

    // 4b. Evaluate policies for this exact model.
    const { data: result, error: rpcError } = await userClient.rpc('evaluate_ai_request', {
      p_organization_id: organization_id,
      p_ai_model_id: modelId,
      p_purpose: isFallback ? `${purpose} (fallback)` : purpose,
      p_data_asset_ids: data_asset_ids,
      p_agent_id: agent_id,
      p_request_type: 'chat',
      p_content_findings: detections,
    });
    if (rpcError) {
      await metric({ provider: candidate.provider, model: candidate.model, outcome: 'error', status_code: 500, error_code: 'policy_evaluation_failed' });
      return json({ error: 'Policy evaluation failed.' }, rpcError.code === '42501' ? 403 : 500, limitHeaders);
    }
    const evaluation = result as {
      request_id: string;
      decision: 'allow' | 'block' | 'review';
      reasons: string[];
      detections: unknown[];
      masked?: boolean;
      approval_required?: boolean;
      approval_request_id?: string | null;
    };

    // 4c. Non-allow decisions end the request — fallbacks never bypass policy.
    if (evaluation.decision === 'block') {
      await metric({ ai_request_id: evaluation.request_id, provider: candidate.provider, model: candidate.model, outcome: 'blocked', status_code: 403, fallback_used: isFallback });
      return json(
        { forwarded: false, decision: 'block', request_id: evaluation.request_id, reasons: evaluation.reasons, detections: evaluation.detections, fallback_used: isFallback, tried },
        403,
        limitHeaders,
      );
    }
    if (evaluation.approval_required || evaluation.decision === 'review') {
      await metric({ ai_request_id: evaluation.request_id, provider: candidate.provider, model: candidate.model, outcome: 'review', status_code: evaluation.approval_required ? 202 : 200, fallback_used: isFallback });
      return json(
        {
          forwarded: false,
          decision: 'review',
          request_id: evaluation.request_id,
          approval_request_id: evaluation.approval_request_id ?? null,
          reasons: evaluation.reasons,
          detections: evaluation.detections,
          fallback_used: isFallback,
          tried,
        },
        evaluation.approval_required ? 202 : 200,
        limitHeaders,
      );
    }

    let apiKey: string;
    try {
      apiKey = await decryptSecret(conn.key_ciphertext as string, conn.key_iv as string);
    } catch {
      await metric({ ai_request_id: evaluation.request_id, provider: candidate.provider, model: candidate.model, outcome: 'error', status_code: 500, error_code: 'decrypt_failed' });
      return json(
        { error: 'Could not decrypt the stored key. The PROVIDER_ENCRYPTION_KEY secret may have changed — reconnect the provider.' },
        500,
        limitHeaders,
      );
    }

    const outgoing: ChatMessage[] =
      evaluation.masked === true
        ? messages.map((m) => ({ ...m, content: maskSensitiveContent(m.content).masked }))
        : messages;

    // 4d. Call the provider with retries.
    const outcome = await callWithRetry({
      adapter: ADAPTERS[candidate.provider],
      apiKey,
      baseUrl: (conn.base_url as string | null) ?? null,
      model: candidate.model,
      messages: outgoing,
      maxAttempts: 3,
      attemptTimeoutMs: 60000,
      deadlineMs: remainingBudget - 1000,
    });
    apiKey = '';
    totalAttempts += outcome.attempts;

    if (isFailedCall(outcome)) {
      lastFailure = {
        code: outcome.error.code,
        status: outcome.error.status,
        message: outcome.error.message,
        request_id: evaluation.request_id,
      };
      tried.push({ provider: candidate.provider, model: candidate.model, error: outcome.error.code });
      await metric({
        ai_request_id: evaluation.request_id,
        provider: candidate.provider,
        model: candidate.model,
        outcome: 'error',
        status_code: outcome.error.status ?? 502,
        provider_latency_ms: outcome.latencyMs,
        attempts: outcome.attempts,
        fallback_used: isFallback,
        error_code: outcome.error.code,
      });
      // Only transient failures fall through to the next candidate.
      if (!outcome.error.retryable) break;
      fallbackUsed = true;
      continue;
    }

    // 5. Scan the output and redact severe findings.
    const outputFindings = detectSensitiveContent(outcome.result.text);
    const redactOutput = shouldRedactOutput(outputFindings, evaluation.masked === true);
    const text = redactOutput ? maskSensitiveContent(outcome.result.text).masked : outcome.result.text;

    const { inputTokens, outputTokens } = outcome.result.usage;
    const costUsd = estimateCostUsd(candidate.provider, candidate.model, inputTokens, outputTokens);

    // 6. Audit + metrics (merged into the evaluation metadata, never replacing it).
    const { data: reqRow } = await admin.from('ai_requests').select('metadata').eq('id', evaluation.request_id).single();
    const existingMeta = ((reqRow as { metadata?: Record<string, unknown> } | null)?.metadata ?? {}) as Record<string, unknown>;
    await admin
      .from('ai_requests')
      .update({
        metadata: {
          ...existingMeta,
          gateway: {
            provider: candidate.provider,
            model: candidate.model,
            masked: evaluation.masked === true,
            output_redacted: redactOutput,
            output_findings: outputFindings,
            fallback_used: isFallback,
            attempts: outcome.attempts,
            latency_ms: outcome.latencyMs,
            input_tokens: inputTokens,
            output_tokens: outputTokens,
            cost_usd: costUsd,
          },
        },
      })
      .eq('id', evaluation.request_id);

    await metric({
      ai_request_id: evaluation.request_id,
      provider: candidate.provider,
      model: candidate.model,
      outcome: 'allowed',
      status_code: 200,
      provider_latency_ms: outcome.latencyMs,
      attempts: outcome.attempts,
      fallback_used: isFallback,
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      cost_usd: costUsd,
      output_findings: outputFindings,
    });

    return json(
      {
        forwarded: true,
        decision: 'allow',
        masked: evaluation.masked === true,
        output_redacted: redactOutput,
        output_findings: outputFindings,
        request_id: evaluation.request_id,
        provider: candidate.provider,
        model: candidate.model,
        fallback_used: isFallback,
        attempts: totalAttempts,
        text,
        usage: { input_tokens: inputTokens, output_tokens: outputTokens, estimated_cost_usd: costUsd },
        tried,
      },
      200,
      limitHeaders,
    );
  }

  // Every candidate failed or was unavailable. Never leak key or provider internals.
  return json(
    {
      forwarded: false,
      decision: 'allow',
      request_id: lastFailure?.request_id ?? null,
      error: lastFailure?.message ?? 'No provider was available for this request.',
      error_code: lastFailure?.code ?? 'no_provider',
      fallback_used: fallbackUsed,
      attempts: totalAttempts,
      tried,
    },
    502,
    limitHeaders,
  );
});
