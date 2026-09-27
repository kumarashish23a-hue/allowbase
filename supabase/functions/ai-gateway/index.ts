// supabase/functions/ai-gateway/index.ts
//
// The Data Control Plane AI gateway: the enforcement point in front of real
// AI providers.
//
// Every request goes through the full pipeline, server-side:
//   1. Authenticate the caller (Supabase Auth) and check org membership.
//   2. Load the organization's provider connection and decrypt the API key.
//      The key never leaves this function and is never logged.
//   3. Scan the prompt for secrets/PII (in memory; raw content is never stored).
//   4. Evaluate policies via the secure evaluate_ai_request Postgres function.
//   5. Block / hold-for-approval / allow. On allow with a mask policy, the
//      detected spans are redacted BEFORE the prompt reaches the provider.
//   6. Forward to the provider and return its answer.
//
// This is what makes "Connect -> Configure -> Protect -> Monitor" real:
// without a policy decision the provider is never called.
//
// POST { organization_id, provider, model, messages, purpose?,
//        data_asset_ids?, agent_id? }
//
// Deploy: supabase functions deploy ai-gateway
// Requires: ai-provider deployed + connected, PROVIDER_ENCRYPTION_KEY secret.

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import { detectSensitiveContent, maskSensitiveContent } from '../_shared/detect.ts';
import { decryptSecret } from '../_shared/providerCrypto.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const PROVIDERS = ['openai', 'anthropic', 'gemini', 'custom'] as const;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GATEWAY_TIMEOUT_MS = 90000;
const MAX_MESSAGES = 50;
const MAX_MESSAGE_CHARS = 50000;

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

function validate(body: Record<string, unknown>): string | null {
  if (!body.organization_id || typeof body.organization_id !== 'string' || !UUID_RE.test(body.organization_id)) {
    return 'organization_id must be a UUID.';
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

serve(async (req: Request): Promise<Response> => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) {
    return json({ error: 'Server misconfigured.' }, 500);
  }

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
  const provider = body.provider as string;
  const model = body.model as string;
  const messages = body.messages as GatewayMessage[];
  const purpose = typeof body.purpose === 'string' && body.purpose.length > 0 ? body.purpose : `AI gateway: ${model}`;
  const data_asset_ids = (body.data_asset_ids as string[] | undefined) ?? [];
  const agent_id = (body.agent_id as string | null | undefined) ?? null;

  // Any active member may call the gateway; policies decide what happens.
  const { data: isMember, error: memberError } = await userClient.rpc('has_org_role', {
    org_id: organization_id,
    allowed: ['owner', 'admin', 'security', 'developer', 'analyst', 'viewer'],
  });
  if (memberError || !isMember) return json({ error: 'Not a member of this organization.' }, 403);

  const admin = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });

  // 2. Load the provider connection and decrypt the key (in memory only).
  const { data: conn, error: connError } = await admin
    .from('ai_provider_connections')
    .select('id,provider,label,base_url,key_ciphertext,key_iv,status')
    .eq('organization_id', organization_id)
    .eq('provider', provider)
    .eq('status', 'active')
    .maybeSingle();
  if (connError || !conn) {
    return json({ error: `No active ${provider} connection. Connect it first in the console.` }, 400);
  }
  let apiKey: string;
  try {
    apiKey = await decryptSecret(
      conn.key_ciphertext as string,
      conn.key_iv as string,
    );
  } catch {
    return json(
      { error: 'Could not decrypt the stored key. The PROVIDER_ENCRYPTION_KEY secret may have changed — reconnect the provider.' },
      500,
    );
  }

  // 3. Scan the prompt for secrets/PII (in memory; raw content is never stored).
  const scanText = messages.map((m) => m.content).join('\n');
  const detections = detectSensitiveContent(scanText);

  // 4. Register the model in the workspace if it is new (external, unapproved
  // by default — policies decide whether it may be used).
  let modelId: string | null = null;
  const { data: existingModel } = await admin
    .from('ai_models')
    .select('id')
    .eq('organization_id', organization_id)
    .eq('provider', conn.label)
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
        provider: conn.label,
        model_identifier: model,
        model_type: 'chat',
        is_external: true,
        is_approved: false,
        risk_level: 'medium',
        metadata: { registered_by: 'ai-gateway' },
      })
      .select('id')
      .single();
    if (modelError || !created) return json({ error: 'Could not register the AI model.' }, 500);
    modelId = (created as { id: string }).id;
  }

  // 5. Evaluate policies (same secure path as the evaluate API).
  const { data: result, error: rpcError } = await userClient.rpc('evaluate_ai_request', {
    p_organization_id: organization_id,
    p_ai_model_id: modelId,
    p_purpose: purpose,
    p_data_asset_ids: data_asset_ids,
    p_agent_id: agent_id,
    p_request_type: 'chat',
    p_content_findings: detections,
  });
  if (rpcError) {
    const status = rpcError.code === '42501' ? 403 : 500;
    return json({ error: 'Policy evaluation failed.' }, status);
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

  if (evaluation.decision === 'block') {
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

  // 6. Allowed — mask first when a mask policy triggered, then forward.
  const outgoing: GatewayMessage[] =
    evaluation.masked === true
      ? messages.map((m) => ({ ...m, content: maskSensitiveContent(m.content).masked }))
      : messages;

  let providerResult: ProviderCall;
  try {
    providerResult = await callProvider(provider, (conn.base_url as string | null) ?? null, apiKey, model, outgoing);
  } catch (error) {
    // Never leak the key or raw provider internals — status line only.
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

  // Stamp the gateway call on the request row for the audit trail
  // (merged into the evaluation metadata, never replacing it).
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
        gateway: { provider, model, masked: evaluation.masked === true },
      },
    })
    .eq('id', evaluation.request_id);

  return json({
    forwarded: true,
    decision: 'allow',
    masked: evaluation.masked === true,
    request_id: evaluation.request_id,
    provider,
    model,
    text: providerResult.text,
    usage: providerResult.usage,
  });
});
