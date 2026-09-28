// supabase/functions/ai-gateway/index.ts
//
// The Data Control Plane AI gateway: the enforcement point in front of real
// AI providers.
//
// Every request goes through the full pipeline, server-side:
//   1. Authenticate the caller: a machine API key with the 'gateway' scope
//      (x-api-key header; the key's organization is authoritative) or a
//      Supabase user session + org membership check.
//   1b. Enforce the rate limit for this endpoint — per API key for machine
//      callers, per organization for human callers (fail-open).
//   2. Load the organization's provider connection and decrypt the API key.
//      The key never leaves this function and is never logged.
//   3. Scan the prompt for secrets/PII (in memory; raw content is never stored).
//   4. Evaluate policies via the secure evaluate_ai_request Postgres function.
//   5. Block / hold-for-approval / allow. On allow with a mask policy, the
//      detected spans are redacted BEFORE the prompt reaches the provider.
//      On allow with a tokenize policy, spans are replaced with vault token
//      ids (reversible for this org's actors; the provider sees only tokens).
//   6. Forward to the provider and return its answer — either as one JSON
//      body (default) or as a sanitized SSE stream (stream: true).
//   7. Scan the provider's RESPONSE for secrets/PII and attack patterns.
//      Non-streaming: the full text is scanned, PII/secrets masked, and
//      token ids detokenized for the org actor before returning.
//      Streaming: each chunk passes through the StreamInspector (2 KB
//      overlap catches secrets split across chunks); critical findings and
//      high-severity attack patterns terminate the stream, high-severity
//      secrets are redacted. Findings are recorded as counts by category
//      (never raw values) in the request metadata.
//
// This is what makes "Connect -> Configure -> Protect -> Monitor" real:
// without a policy decision the provider is never called.
//
// POST { organization_id, provider, model, messages, purpose?,
//        data_asset_ids?, agent_id? }
//
// Deploy: supabase functions deploy ai-gateway
// Requires: ai-provider deployed + connected, PROVIDER_ENCRYPTION_KEY secret.
// TOKEN_ENCRYPTION_KEY is additionally required when any tokenize policy is
// used (the gateway fails closed without it).

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import type { SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import { detectSensitiveContent, maskSensitiveContent, hasCriticalFinding, DETECTOR_VERSION } from '../_shared/detect.ts';
import { detectThreats, hasCriticalThreat, THREAT_DETECTOR_VERSION } from '../_shared/threat.ts';
import { tokenize, detokenize } from '../_shared/tokenize.ts';
import type { TokenVault, StoredToken } from '../_shared/tokenize.ts';
import { StreamInspector, STREAM_INSPECTOR_VERSION } from '../_shared/streamInspect.ts';
import { checkEndpointRateLimit, rateLimitedResponse } from '../_shared/rateLimit.ts';
import { recordMetric, nowMs } from '../_shared/metrics.ts';
import { decryptSecret } from '../_shared/providerCrypto.ts';
import { extractApiKey, sha256Hex, verifyApiKeyForScope } from '../_shared/apiKeys.ts';
import { isSafeProviderUrlAsync } from '../_shared/ssrf.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-api-key',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const PROVIDERS = ['openai', 'anthropic', 'gemini', 'custom'] as const;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GATEWAY_TIMEOUT_MS = 90000;
const MAX_MESSAGES = 50;
const MAX_MESSAGE_CHARS = 50000;
// Provider response text is scanned for sensitive content up to this cap;
// the full response is still masked before being returned.
const RESPONSE_SCAN_MAX_CHARS = 100 * 1024;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

interface GatewayMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

function validate(body: Record<string, unknown>, requireOrg: boolean): string | null {
  if (requireOrg) {
    // Human (JWT) callers must name the organization they act on.
    // Machine callers are bound to the key's organization instead.
    if (!body.organization_id || typeof body.organization_id !== 'string' || !UUID_RE.test(body.organization_id)) {
      return 'organization_id must be a UUID.';
    }
  }
  if (!body.provider || typeof body.provider !== 'string' || !(PROVIDERS as readonly string[]).includes(body.provider)) {
    return `provider must be one of: ${PROVIDERS.join(', ')}.`;
  }
  if (!body.model || typeof body.model !== 'string' || body.model.length === 0 || body.model.length > 120) {
    return 'model is required (max 120 chars).';
  }
  if (!Array.isArray(body.messages) || body.messages.length === 0 || body.messages.length > MAX_MESSAGES) {
    return `messages must be a non-empty array (max ${MAX_MESSAGES}).`;
  }
  for (const m of body.messages as unknown[]) {
    const msg = m as Partial<GatewayMessage>;
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
    if (!Array.isArray(body.data_asset_ids) || !(body.data_asset_ids as unknown[]).every((id) => typeof id === 'string' && UUID_RE.test(id))) {
      return 'data_asset_ids must be an array of UUIDs.';
    }
  }
  if (body.agent_id !== undefined && body.agent_id !== null && (typeof body.agent_id !== 'string' || !UUID_RE.test(body.agent_id))) {
    return 'agent_id must be a UUID or null.';
  }
  if (body.stream !== undefined && typeof body.stream !== 'boolean') {
    return 'stream must be a boolean.';
  }
  return null;
}

interface ProviderCall {
  text: string;
  usage: Record<string, unknown> | null;
}

async function postJson(url: string, headers: Record<string, string>, body: unknown): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
  });
}

/** Merge consecutive same-role messages; providers reject role repeats. */
function normalizeRoles(messages: GatewayMessage[]): GatewayMessage[] {
  const out: GatewayMessage[] = [];
  for (const m of messages) {
    const last = out[out.length - 1];
    if (last && last.role === m.role) last.content += '\n' + m.content;
    else out.push({ ...m });
  }
  return out;
}

async function callProvider(
  provider: string,
  baseUrl: string | null,
  apiKey: string,
  model: string,
  messages: GatewayMessage[],
): Promise<ProviderCall> {
  if (provider === 'openai' || provider === 'custom') {
    const base = (baseUrl ?? 'https://api.openai.com/v1').replace(/\/$/, '');
    const res = await postJson(
      `${base}/chat/completions`,
      { Authorization: `Bearer ${apiKey}` },
      { model, messages: messages.map((m) => ({ role: m.role, content: m.content })) },
    );
    if (!res.ok) throw new Error(`Provider returned ${res.status}.`);
    const data = (await res.json()) as {
      choices?: { message?: { content?: string } }[];
      usage?: Record<string, unknown>;
    };
    return { text: data.choices?.[0]?.message?.content ?? '', usage: data.usage ?? null };
  }
  if (provider === 'anthropic') {
    const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
    const convo = normalizeRoles(messages.filter((m) => m.role !== 'system')).map((m) => ({
      role: m.role as 'user' | 'assistant',
      content: m.content,
    }));
    const res = await postJson(
      'https://api.anthropic.com/v1/messages',
      { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      { model, max_tokens: 2048, ...(system ? { system } : {}), messages: convo },
    );
    if (!res.ok) throw new Error(`Provider returned ${res.status}.`);
    const data = (await res.json()) as {
      content?: { type?: string; text?: string }[];
      usage?: Record<string, unknown>;
    };
    const text = (data.content ?? []).filter((b) => b.type === 'text').map((b) => b.text ?? '').join('');
    return { text, usage: data.usage ?? null };
  }
  // gemini
  const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
  const contents = normalizeRoles(messages.filter((m) => m.role !== 'system')).map((m) => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }],
  }));
  const res = await postJson(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
    { 'x-goog-api-key': apiKey },
    { ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}), contents },
  );
  if (!res.ok) throw new Error(`Provider returned ${res.status}.`);
  const data = (await res.json()) as {
    candidates?: { content?: { parts?: { text?: string }[] } }[];
    usageMetadata?: Record<string, unknown>;
  };
  const text = (data.candidates?.[0]?.content?.parts ?? []).map((p) => p.text ?? '').join('');
  return { text, usage: data.usageMetadata ?? null };
}

interface StreamParams {
  admin: SupabaseClient;
  organizationId: string;
  callerUserId: string | null;
  provider: string;
  storedBase: string | null;
  apiKey: string;
  model: string;
  outgoing: GatewayMessage[];
  tokenVault: TokenVault;
  tokenizedOut: boolean;
  requestId: string;
  meter: (status: 'ok' | 'error' | 'rate_limited', errorCode?: string | null) => void;
}

/**
 * Phase D: streaming provider call with output inspection (OpenAI SSE first).
 *
 * The provider's SSE stream is parsed chunk by chunk; each content delta
 * goes through a StreamInspector (2 KB overlap catches secrets split
 * across chunks) before anything reaches the caller:
 * - critical secret/key or critical/high attack pattern -> the provider
 *   stream is cancelled, the caller gets a termination event, and an
 *   audit row is written (response-side blocking).
 * - high-severity secret (SSN, card, ...) -> the span is redacted in flight.
 * - medium/low -> passed through; counted for the audit trail.
 *
 * When the request was tokenized, a 64-char-overlap detokenize stage sits
 * between the inspector and the caller (token ids are 30 chars, so a split
 * id is always completed before resolve). Inspection runs BEFORE
 * detokenization — the restored values belong to this org's authorized
 * actor and must not be re-inspected (mask-before-detokenize order).
 *
 * Caller protocol (text/event-stream):
 *   data: {"type":"start","request_id":...}
 *   data: {"type":"content","content":"..."}   (sanitized deltas)
 *   data: {"type":"done","terminated":bool,"terminate_reason":...,"usage":...}
 *   data: [DONE]
 */
async function streamProviderResponse(p: StreamParams): Promise<Response> {
  const base = (p.storedBase ?? 'https://api.openai.com/v1').replace(/\/$/, '');
  const res = await fetch(`${base}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
      Authorization: `Bearer ${p.apiKey}`,
    },
    body: JSON.stringify({
      model: p.model,
      messages: p.outgoing.map((m) => ({ role: m.role, content: m.content })),
      stream: true,
      stream_options: { include_usage: true },
    }),
    signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
  });
  if (!res.ok || !res.body) throw new Error(`Provider returned ${res.status}.`);

  const inspector = new StreamInspector();
  const tokenKey = p.tokenizedOut ? (Deno.env.get('TOKEN_ENCRYPTION_KEY') ?? '') : '';
  // Outbound already failed closed without the key, so it exists here; if it
  // vanished mid-request (rotation) token ids stay opaque rather than
  // failing the whole stream.
  const tokenKeyOk = /^[0-9a-fA-F]{64}$/.test(tokenKey);
  const actorType = p.callerUserId ? 'user' : 'machine_key';

  let detokCarry = '';
  let usage: Record<string, unknown> | null = null;
  let streamTerminated = false;
  let terminateReason: string | null = null;

  const encoder = new TextEncoder();
  const sse = (obj: unknown): Uint8Array => encoder.encode(`data: ${JSON.stringify(obj)}\n\n`);

  /** Detokenize with a 64-char holdback so split token ids resolve whole. */
  async function detokEmit(text: string, isFinal: boolean): Promise<string> {
    if (!p.tokenizedOut || !tokenKeyOk) return text;
    const combined = detokCarry + text;
    const processUpTo = isFinal ? combined.length : Math.max(0, combined.length - 64);
    const toProcess = combined.slice(0, processUpTo);
    detokCarry = combined.slice(processUpTo);
    if (!toProcess) return '';
    const de = await detokenize(toProcess, {
      vault: p.tokenVault,
      organizationId: p.organizationId,
      encryptionKeyHex: tokenKey,
      actorUserId: p.callerUserId,
      actorType,
    });
    return de.text;
  }

  async function stampStreamAudit(): Promise<void> {
    const summary = inspector.summary();
    try {
      const { data: reqRow } = await p.admin
        .from('ai_requests')
        .select('metadata')
        .eq('id', p.requestId)
        .single();
      const existingMeta = ((reqRow as { metadata?: Record<string, unknown> } | null)?.metadata ?? {}) as Record<
        string,
        unknown
      >;
      await p.admin
        .from('ai_requests')
        .update({
          metadata: {
            ...existingMeta,
            gateway: {
              ...((existingMeta.gateway ?? {}) as Record<string, unknown>),
              stream: {
                inspector: STREAM_INSPECTOR_VERSION,
                chunks: summary.chunks,
                bytes: summary.bytes,
                terminated: summary.terminated,
                terminate_reason: summary.terminateReason,
                counts_by_category: summary.countsByCategory,
                redactions: summary.redactions,
                usage,
              },
            },
          },
        })
        .eq('id', p.requestId);
      if (summary.terminated) {
        await p.admin.from('audit_logs').insert({
          organization_id: p.organizationId,
          actor_user_id: p.callerUserId,
          actor_type: actorType,
          action: 'stream_terminated',
          resource_type: 'ai_request',
          resource_id: p.requestId,
          result: 'terminated',
          // Categories and counts only — never raw matched values.
          metadata: {
            reason: summary.terminateReason,
            inspector: STREAM_INSPECTOR_VERSION,
            counts_by_category: summary.countsByCategory,
            chunks: summary.chunks,
            bytes: summary.bytes,
          },
        });
      }
    } catch {
      /* audit stamp is best-effort */
    }
  }

  const body = new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        controller.enqueue(sse({ type: 'start', request_id: p.requestId, provider: p.provider, model: p.model }));
        const reader = res.body!.getReader();
        const decoder = new TextDecoder();
        let sseBuf = '';
        let providerDone = false;
        while (!providerDone) {
          const { done, value } = await reader.read();
          if (done) break;
          sseBuf += decoder.decode(value, { stream: true });
          let idx: number;
          while (!providerDone && (idx = sseBuf.indexOf('\n\n')) !== -1) {
            const event = sseBuf.slice(0, idx);
            sseBuf = sseBuf.slice(idx + 2);
            for (const line of event.split('\n')) {
              const t = line.trim();
              if (!t.startsWith('data:')) continue;
              const data = t.slice(5).trim();
              if (data === '[DONE]') {
                providerDone = true;
                break;
              }
              let payload: {
                choices?: { delta?: { content?: string }; message?: { content?: string } }[];
                usage?: Record<string, unknown>;
              };
              try {
                payload = JSON.parse(data);
              } catch {
                continue;
              }
              if (payload.usage) usage = payload.usage;
              const delta =
                payload.choices?.[0]?.delta?.content ?? payload.choices?.[0]?.message?.content ?? '';
              if (typeof delta !== 'string' || delta.length === 0) continue;
              const step = inspector.inspect(delta);
              if (step.terminated) {
                streamTerminated = true;
                terminateReason = step.terminateReason;
                providerDone = true;
                try {
                  await reader.cancel();
                } catch {
                  /* provider stream already closing */
                }
                break;
              }
              if (step.output) {
                const out = await detokEmit(step.output, false);
                if (out) controller.enqueue(sse({ type: 'content', content: out }));
              }
            }
          }
        }
        if (!streamTerminated) {
          const fin = inspector.finalize();
          if (fin.terminated) {
            streamTerminated = true;
            terminateReason = fin.terminateReason;
          } else {
            if (fin.output) {
              const out = await detokEmit(fin.output, true);
              if (out) controller.enqueue(sse({ type: 'content', content: out }));
            } else if (detokCarry) {
              const out = await detokEmit('', true);
              if (out) controller.enqueue(sse({ type: 'content', content: out }));
            }
          }
        }
        await stampStreamAudit();
        controller.enqueue(
          sse({
            type: 'done',
            terminated: streamTerminated,
            terminate_reason: terminateReason,
            request_id: p.requestId,
            usage,
          }),
        );
        controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        controller.close();
      } catch {
        try {
          controller.enqueue(sse({ type: 'error', error: 'Streaming failed.' }));
        } catch {
          /* controller already closed */
        }
        controller.close();
      }
    },
  });

  p.meter('ok');
  return new Response(body, {
    headers: {
      ...corsHeaders,
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'X-Accel-Buffering': 'no',
    },
  });
}

serve(async (req: Request): Promise<Response> => {
  const t0 = nowMs();
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) {
    return json({ error: 'Server misconfigured.' }, 500);
  }

  // 1. Authenticate the caller: a machine API key (x-api-key header carrying a
  //    key with the 'gateway' scope) or a Supabase user session. An API key
  //    authenticates the *organization* — the key's organization is
  //    authoritative and any body organization_id is ignored, so a key can
  //    never act on another org. (JWTs never start with dcp_, so the two
  //    credentials never collide.)
  const admin = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });

  let apiKeyHash: string | null = null;
  let keyOrganizationId: string | null = null;
  // The human caller's user id (JWT path only); used for token-vault auditing.
  let callerUserId: string | null = null;
  // Set on the JWT path only; the machine-key path never touches it.
  let userClient: SupabaseClient | null = null;
  const rawApiKey = extractApiKey(req);
  if (rawApiKey) {
    apiKeyHash = await sha256Hex(rawApiKey);
    const verified = await verifyApiKeyForScope(admin, apiKeyHash, 'gateway');
    if (!verified.ok) {
      // 401 = bad key; 500 = our own verification broke (never disguise an
      // outage as a bad key).
      return json({ error: verified.status === 401 ? 'Invalid API key.' : 'Key verification failed.' }, verified.status);
    }
    keyOrganizationId = verified.key.organizationId;
  }

  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400);
  }
  const validationError = validate(body, !keyOrganizationId);
  if (validationError) return json({ error: validationError }, 400);

  // The key's organization is authoritative; the body field exists only for
  // the JWT path and is ignored for machine callers.
  const organization_id = keyOrganizationId ?? (body.organization_id as string);

  if (!keyOrganizationId) {
    const authHeader = req.headers.get('Authorization');
    if (!authHeader?.startsWith('Bearer ')) return json({ error: 'Missing authorization.' }, 401);
    const jwtClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false },
    });
    userClient = jwtClient;
    const {
      data: { user },
      error: userError,
    } = await jwtClient.auth.getUser();
    if (userError || !user) return json({ error: 'Invalid or expired session.' }, 401);
    callerUserId = user.id;

    // Calling the gateway spends real provider quota, so viewers and
    // analysts are excluded — same posture as connecting a provider.
    const { data: isMember, error: memberError } = await jwtClient.rpc('has_org_role', {
      org_id: organization_id,
      allowed: ['owner', 'admin', 'security', 'developer'],
    });
    if (memberError || !isMember) return json({ error: 'Not authorized to use the gateway.' }, 403);
  }

  const provider = body.provider as string;
  const model = body.model as string;
  const messages = body.messages as GatewayMessage[];
  const purpose = typeof body.purpose === 'string' && body.purpose.length > 0 ? body.purpose : `AI gateway: ${model}`;
  const data_asset_ids = (body.data_asset_ids as string[] | undefined) ?? [];
  const agent_id = (body.agent_id as string | null | undefined) ?? null;

  // Best-effort production metrics (fire-and-forget; never fails the request).
  // 4xx caller errors are recorded as 'ok' with an errorCode so error_rate
  // stays a true function-health signal; only 5xx counts as 'error'.
  const meter = (status: 'ok' | 'error' | 'rate_limited', errorCode?: string | null) =>
    recordMetric(admin, {
      functionName: 'ai-gateway',
      organizationId: organization_id,
      status,
      latencyMs: nowMs() - t0,
      errorCode: errorCode ?? null,
    });

  // 1b. Rate limit this endpoint: per API key for machine callers, per
  // organization for human callers. Fail-open: the helper allows the request
  // when the limiter itself errors, so this is a protective control, not the
  // auth boundary.
  const rateLimit = await checkEndpointRateLimit(
    admin,
    'ai-gateway',
    apiKeyHash ? `key:${apiKeyHash}` : organization_id,
  );
  if (!rateLimit.allowed) {
    meter('rate_limited');
    return rateLimitedResponse(rateLimit.retryAfter, corsHeaders);
  }

  // 2. Load the provider connection and decrypt the key (in memory only).
  const { data: conn, error: connError } = await admin
    .from('ai_provider_connections')
    .select('id,provider,label,base_url,key_ciphertext,key_iv,status')
    .eq('organization_id', organization_id)
    .eq('provider', provider)
    .eq('status', 'active')
    .maybeSingle();
  if (connError || !conn) {
    meter('ok', 'no_connection');
    return json({ error: `No active ${provider} connection. Connect it first in the console.` }, 400);
  }
  let apiKey: string;
  try {
    apiKey = await decryptSecret(
      conn.key_ciphertext as string,
      conn.key_iv as string,
    );
  } catch {
    meter('error', 'decrypt_error');
    return json(
      { error: 'Could not decrypt the stored key. The PROVIDER_ENCRYPTION_KEY secret may have changed — reconnect the provider.' },
      500,
    );
  }

  // 3. Scan the prompt for secrets/PII and for attack patterns (in memory;
  //    raw content is never stored). Threat findings travel in the same
  //    findings array so threat.category policy conditions can match them.
  const scanText = messages.map((m) => m.content).join('\n');
  const detections = [...detectSensitiveContent(scanText), ...detectThreats(scanText)];

  // 4. Register the model in the workspace if it is new (external, unapproved
  // by default — policies decide whether it may be used). Matched on the
  // provider *id* (openai / anthropic / …), never the display label, so
  // ai.provider policies hit the same rows the gateway registers.
  let modelId: string | null = null;
  const { data: existingModel } = await admin
    .from('ai_models')
    .select('id')
    .eq('organization_id', organization_id)
    .eq('provider', conn.provider)
    .eq('name', model)
    .maybeSingle();
  if (existingModel) {
    modelId = (existingModel as { id: string }).id;
  } else {
    const { data: created, error: modelError } = await admin
      .from('ai_models')
      .insert({
        organization_id,
        name: model,
        provider: conn.provider,
        model_identifier: model,
        model_type: 'chat',
        is_external: true,
        is_approved: false,
        risk_level: 'medium',
        metadata: { registered_by: 'ai-gateway' },
      })
      .select('id')
      .single();
    if (modelError || !created) {
      // 23505: a concurrent request registered the same model first (the
      // uq_ai_models_org_provider_name constraint from 026). Re-read the
      // winner instead of failing the request.
      if ((modelError as { code?: string })?.code === '23505') {
        const { data: raced } = await admin
          .from('ai_models')
          .select('id')
          .eq('organization_id', organization_id)
          .eq('provider', conn.provider)
          .eq('name', model)
          .maybeSingle();
        if (raced) {
          modelId = (raced as { id: string }).id;
        } else {
          return json({ error: 'Could not register the AI model.' }, 500);
        }
      } else {
        return json({ error: 'Could not register the AI model.' }, 500);
      }
    } else {
      modelId = (created as { id: string }).id;
    }
  }

  // 5. Evaluate policies through the secure evaluator.
  //    Lazy approval expiry (no pg_cron): sweep stale approvals best-effort
  //    before every evaluation. decide_approval sweeps again itself, so an
  //    expired approval can never be decided even if this sweep fails.
  try {
    await admin.rpc('expire_stale_approvals');
  } catch {
    /* hygiene only — never fail the request */
  }
  //    Machine callers go through the service-role wrapper
  //    evaluate_gateway_request, which re-verifies the key and stamps the
  //    transaction-local app.api_key_id trust marker the evaluator requires.
  //    Never call evaluate_ai_request as service_role without that stamp —
  //    service_role has no auth.uid(), so the membership check would 42501.
  //    Human callers call evaluate_ai_request as themselves, so the
  //    evaluator's is_org_member check runs against their verified JWT.
  let result: unknown;
  let rpcError: { code?: string; message?: string } | null;
  if (keyOrganizationId && apiKeyHash) {
    ({ data: result, error: rpcError } = await admin.rpc('evaluate_gateway_request', {
      p_key_hash: apiKeyHash,
      p_organization_id: organization_id,
      p_ai_model_id: modelId,
      p_purpose: purpose,
      p_data_asset_ids: data_asset_ids,
      p_agent_id: agent_id,
      p_request_type: 'chat',
      p_content_findings: detections,
    }));
  } else if (userClient) {
    ({ data: result, error: rpcError } = await userClient.rpc('evaluate_ai_request', {
      p_organization_id: organization_id,
      p_ai_model_id: modelId,
      p_purpose: purpose,
      p_data_asset_ids: data_asset_ids,
      p_agent_id: agent_id,
      p_request_type: 'chat',
      p_content_findings: detections,
    }));
  } else {
    // Unreachable: auth above guarantees one of the two paths.
    return json({ error: 'Not authenticated.' }, 401);
  }
  if (rpcError) {
    const status = rpcError.code === '42501' ? 403 : 500;
    meter(status === 500 ? 'error' : 'ok', status === 500 ? 'policy_eval_error' : 'not_member');
    return json({ error: 'Policy evaluation failed.' }, status);
  }
  const evaluation = result as {
    request_id: string;
    decision: 'allow' | 'block' | 'review';
    reasons: string[];
    detections: unknown[];
    masked?: boolean;
    tokenized?: boolean;
    approval_required?: boolean;
    approval_request_id?: string | null;
  };

  if (evaluation.decision === 'block') {
    meter('ok', 'policy_block');
    return json(
      {
        forwarded: false,
        decision: 'block',
        request_id: evaluation.request_id,
        reasons: evaluation.reasons,
        detections: evaluation.detections,
      },
      403,
    );
  }
  if (evaluation.approval_required) {
    meter('ok', 'approval_required');
    return json(
      {
        forwarded: false,
        decision: 'review',
        request_id: evaluation.request_id,
        approval_request_id: evaluation.approval_request_id,
        reasons: evaluation.reasons,
      },
      202,
    );
  }
  if (evaluation.decision === 'review') {
    meter('ok', 'policy_review');
    return json(
      {
        forwarded: false,
        decision: 'review',
        request_id: evaluation.request_id,
        reasons: evaluation.reasons,
        detections: evaluation.detections,
      },
      200,
    );
  }

  // 6. Allowed — transform first when a transform policy triggered, then forward.
  //    mask: destructive redaction before the provider sees the prompt.
  //    tokenize: reversible substitution via the privacy vault (token ids go
  //    to the provider; originals are AES-GCM encrypted at rest and restored
  //    only for this organization's authorized actors on the way back).
  const tokenVault: TokenVault = {
    create: async (entry) => {
      const { error } = await admin.from('privacy_tokens').insert(entry);
      if (error) throw new Error(`token vault write failed: ${error.message}`);
    },
    lookup: async (token_id) => {
      const { data, error } = await admin
        .from('privacy_tokens')
        .select('token_id, organization_id, value_encrypted, value_iv, purpose, expires_at, revoked_at')
        .eq('token_id', token_id)
        .maybeSingle();
      if (error) throw new Error(`token vault read failed: ${error.message}`);
      return (data as StoredToken | null) ?? null;
    },
    recordResolve: async (token_id) => {
      const { data } = await admin
        .from('privacy_tokens')
        .select('resolved_count')
        .eq('token_id', token_id)
        .maybeSingle();
      await admin
        .from('privacy_tokens')
        .update({
          resolved_count: ((data as { resolved_count?: number } | null)?.resolved_count ?? 0) + 1,
          last_resolved_at: new Date().toISOString(),
        })
        .eq('token_id', token_id);
    },
    audit: async (entry) => {
      const { error } = await admin.from('audit_logs').insert(entry);
      if (error) throw new Error(`token vault audit failed: ${error.message}`);
    },
  };

  let outgoing: GatewayMessage[] = messages;
  let tokenizeCount = 0;
  if (evaluation.masked === true) {
    outgoing = messages.map((m) => ({ ...m, content: maskSensitiveContent(m.content).masked }));
  } else if (evaluation.tokenized === true) {
    const tokenKey = Deno.env.get('TOKEN_ENCRYPTION_KEY') ?? '';
    if (!/^[0-9a-fA-F]{64}$/.test(tokenKey)) {
      // Fail closed: a tokenize policy fired but the vault key is missing.
      // Sending the raw prompt would silently downgrade the protection.
      meter('error', 'token_key_missing');
      return json(
        { error: 'A tokenize policy matched but TOKEN_ENCRYPTION_KEY is not configured. Set it with: supabase secrets set TOKEN_ENCRYPTION_KEY=$(openssl rand -hex 32)' },
        500,
      );
    }
    const tokenized = await Promise.all(
      messages.map((m) =>
        tokenize(m.content, detections as Array<{ category: string }>, {
          vault: tokenVault,
          organizationId: organization_id,
          encryptionKeyHex: tokenKey,
          actorUserId: callerUserId,
          actorType: callerUserId ? 'user' : 'machine_key',
        }),
      ),
    );
    outgoing = messages.map((m, i) => ({ ...m, content: tokenized[i].text }));
    tokenizeCount = tokenized.reduce((n, t) => n + t.tokens.length, 0);
  }

  let providerResult: ProviderCall;
  try {
    // Re-validate the stored URL on every call, not just at connect time:
    // the row may predate the SSRF check, or the check may have tightened.
    // The async check resolves the hostname and refuses when ANY resolved
    // IP is private/loopback/link-local (resolve-then-check).
    const storedBase = (conn.base_url as string | null) ?? null;
    if (provider === 'custom' && storedBase && !(await isSafeProviderUrlAsync(storedBase))) {
      meter('error', 'unsafe_base_url');
      return json(
        { error: 'The stored provider URL failed the safety check. Reconnect the provider with a public https URL.' },
        500,
      );
    }
    // Phase D: streaming inspection (OpenAI SSE first). The streaming path
    // returns its own Response; the finally below still redacts the key,
    // and the stream audit stamp is written when the stream ends.
    const wantStream = body.stream === true;
    if (wantStream && provider !== 'openai' && provider !== 'custom') {
      meter('ok', 'stream_unsupported');
      return json({ error: 'Streaming inspection is currently supported for openai/custom providers only.' }, 400);
    }
    if (wantStream) {
      return await streamProviderResponse({
        admin,
        organizationId: organization_id,
        callerUserId,
        provider,
        storedBase,
        apiKey,
        model,
        outgoing,
        tokenVault,
        tokenizedOut: evaluation.tokenized === true,
        requestId: evaluation.request_id,
        meter,
      });
    }
    providerResult = await callProvider(provider, storedBase, apiKey, model, outgoing);
  } catch (error) {
    // Never leak the key or raw provider internals — status line only.
    meter('error', 'provider_error');
    return json(
      {
        forwarded: false,
        decision: 'allow',
        request_id: evaluation.request_id,
        error: error instanceof Error ? error.message : 'The AI provider request failed.',
      },
      502,
    );
  } finally {
    apiKey = '';
  }

  // 7. Scan the provider's response for sensitive content and attack patterns
  //    (in memory; raw response text is never stored) and mask PII/secrets
  //    before returning it to the caller. Threat-scanning the response
  //    matters because indirect prompt injection and malicious instructions
  //    can arrive via tool/RAG output the provider echoes back. Only the
  //    first RESPONSE_SCAN_MAX_CHARS are scanned; masking applies to the
  //    full response. Findings are recorded as counts by category — never
  //    raw values.
  const responseScanText = providerResult.text.slice(0, RESPONSE_SCAN_MAX_CHARS);
  const responseContentFindings = detectSensitiveContent(responseScanText);
  const responseThreatFindings = detectThreats(responseScanText);
  const responseFindings = [...responseContentFindings, ...responseThreatFindings];
  const maskedResponse = maskSensitiveContent(providerResult.text);
  const responseMaskedCritical = hasCriticalFinding(responseContentFindings);

  // Detokenize AFTER masking: token ids (abt_tok_...) match no detection
  // rule, so they survive masking — model-introduced secrets are still
  // caught while this org's authorized actor gets their real values back.
  // Unknown, expired, revoked, or foreign-org tokens stay opaque and are
  // counted, never resolved. If the vault key vanished between outbound
  // and inbound (rotation), tokens stay opaque rather than failing the
  // whole response — the provider only ever saw token ids anyway.
  let responseText = maskedResponse.masked;
  let tokensResolved = 0;
  let tokensUnresolved = 0;
  if (evaluation.tokenized === true) {
    const tokenKey = Deno.env.get('TOKEN_ENCRYPTION_KEY') ?? '';
    if (/^[0-9a-fA-F]{64}$/.test(tokenKey)) {
      const de = await detokenize(maskedResponse.masked, {
        vault: tokenVault,
        organizationId: organization_id,
        encryptionKeyHex: tokenKey,
        actorUserId: callerUserId,
        actorType: callerUserId ? 'user' : 'machine_key',
      });
      responseText = de.text;
      tokensResolved = de.resolved;
      tokensUnresolved = de.unresolved;
    } else {
      tokensUnresolved = (maskedResponse.masked.match(/abt_tok_[A-Za-z0-9_-]{22}/g) ?? []).length;
    }
  }

  // Stamp the gateway call on the request row for the audit trail
  // (merged into the evaluation metadata, never replacing it).
  // Best-effort: an audit-write failure must not fail the user's request.
  try {
    const { data: reqRow } = await admin
      .from('ai_requests')
      .select('metadata')
      .eq('id', evaluation.request_id)
      .single();
    const existingMeta = ((reqRow as { metadata?: Record<string, unknown> } | null)?.metadata ?? {}) as Record<
      string,
      unknown
    >;
    await admin
      .from('ai_requests')
      .update({
        metadata: {
          ...existingMeta,
          gateway: {
            provider,
            model,
            masked: evaluation.masked === true,
            tokenized: evaluation.tokenized === true,
            tokens_created: tokenizeCount,
            tokens_resolved: tokensResolved,
            tokens_unresolved: tokensUnresolved,
            response_scan: {
              detector: DETECTOR_VERSION,
              threat_detector: THREAT_DETECTOR_VERSION,
              // Counts by category only — raw matched values never leave the detectors.
              counts_by_category: Object.fromEntries(responseFindings.map((f) => [f.category, f.count])),
              spans_masked: maskedResponse.maskedCount,
              response_masked: responseMaskedCritical,
              // A critical threat in the response (e.g. destructive commands
              // the model generated) is surfaced here. The non-streaming
              // path still only surfaces it; the streaming path (stream:
              // true) terminates the stream on critical findings and
              // high-severity attack patterns — that is the response-side
              // blocking.
              threat_critical: hasCriticalThreat(responseThreatFindings),
            },
          },
        },
      })
      .eq('id', evaluation.request_id);
  } catch {
    /* audit stamp is best-effort */
  }

  meter('ok');
  return json({
    forwarded: true,
    decision: 'allow',
    masked: evaluation.masked === true,
    tokenized: evaluation.tokenized === true,
    tokens_created: tokenizeCount,
    tokens_resolved: tokensResolved,
    tokens_unresolved: tokensUnresolved,
    request_id: evaluation.request_id,
    provider,
    model,
    text: responseText,
    usage: providerResult.usage,
  });
});
