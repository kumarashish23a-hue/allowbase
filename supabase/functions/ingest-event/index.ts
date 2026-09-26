// supabase/functions/ingest-event/index.ts
//
// The front door of the control plane: a customer backend POSTs an AI data
// request here *before* calling the model. The function authenticates the
// organization via an API key (x-api-key header), runs the deterministic
// policy engine, and returns ALLOW / BLOCK / REVIEW.
//
// Deploy: supabase functions deploy ingest-event
//
// Request:
//   POST /functions/v1/ingest-event
//   x-api-key: dcp_live_...
//   {
//     "event_id": "evt_9f32c1",        // required, idempotency key (1-200 chars)
//     "model_name": "support-copilot", // or "ai_model_id" (uuid)
//     "purpose": "customer-support",   // required
//     "data_asset_ids": ["<uuid>"],    // optional
//     "agent_name": "triage-bot",      // optional; unknown names fail closed
//     "request_type": "api"            // optional
//   }
//
// Response: { request_id, decision, risk, reasons, policies_triggered, checks,
//             event_id, idempotent_replay }
//   decision: "allow" | "block" | "review" | "require_approval"

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-api-key',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64_RE = /^[0-9a-f]{64}$/;

interface IngestPayload {
  event_id?: unknown;
  ai_model_id?: unknown;
  model_name?: unknown;
  purpose?: unknown;
  data_asset_ids?: unknown;
  agent_name?: unknown;
  request_type?: unknown;
}

function json(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

serve(async (req: Request): Promise<Response> => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }
  if (req.method !== 'POST') {
    return json(405, { error: 'Method not allowed' });
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !serviceKey) {
    return json(500, { error: 'Server misconfigured' });
  }

  // 1. Authenticate: API key from x-api-key, or a Bearer token shaped like one.
  //    (JWTs never start with dcp_, so the two never collide.)
  let apiKey = req.headers.get('x-api-key')?.trim() ?? '';
  const authHeader = req.headers.get('Authorization') ?? '';
  if (!apiKey && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice('Bearer '.length).trim();
    if (token.startsWith('dcp_')) apiKey = token;
  }
  if (!apiKey.startsWith('dcp_live_') || apiKey.length < 20 || apiKey.length > 200) {
    return json(401, { error: 'Invalid API key' });
  }
  const keyHash = await sha256Hex(apiKey);

  // 2. Validate the payload (never trust the caller).
  let body: IngestPayload;
  try {
    body = await req.json();
  } catch {
    return json(400, { error: 'Request body must be valid JSON.' });
  }

  const eventId = body.event_id;
  if (typeof eventId !== 'string' || eventId.length === 0 || eventId.length > 200) {
    return json(400, { error: 'event_id is required (1-200 characters).' });
  }
  const purpose = body.purpose;
  if (typeof purpose !== 'string' || purpose.length === 0 || purpose.length > 500) {
    return json(400, { error: 'purpose is required (1-500 characters).' });
  }

  let aiModelId: string | null = null;
  if (body.ai_model_id !== undefined && body.ai_model_id !== null) {
    if (typeof body.ai_model_id !== 'string' || !UUID_RE.test(body.ai_model_id)) {
      return json(400, { error: 'ai_model_id must be a UUID when provided.' });
    }
    aiModelId = body.ai_model_id;
  }
  let modelName: string | null = null;
  if (body.model_name !== undefined && body.model_name !== null) {
    if (typeof body.model_name !== 'string' || body.model_name.length === 0 || body.model_name.length > 120) {
      return json(400, { error: 'model_name must be 1-120 characters when provided.' });
    }
    modelName = body.model_name;
  }
  if (!aiModelId && !modelName) {
    return json(400, { error: 'ai_model_id or model_name is required.' });
  }

  let assetIds: string[] = [];
  if (body.data_asset_ids !== undefined && body.data_asset_ids !== null) {
    if (!Array.isArray(body.data_asset_ids) || body.data_asset_ids.length > 200) {
      return json(400, { error: 'data_asset_ids must be an array of at most 200 UUIDs.' });
    }
    for (const id of body.data_asset_ids) {
      if (typeof id !== 'string' || !UUID_RE.test(id)) {
        return json(400, { error: 'data_asset_ids must contain only UUIDs.' });
      }
    }
    assetIds = body.data_asset_ids as string[];
  }

  let agentName: string | null = null;
  if (body.agent_name !== undefined && body.agent_name !== null) {
    if (typeof body.agent_name !== 'string' || body.agent_name.length === 0 || body.agent_name.length > 120) {
      return json(400, { error: 'agent_name must be 1-120 characters when provided.' });
    }
    agentName = body.agent_name;
  }

  const VALID_REQUEST_TYPES = ['chat', 'completion', 'agent_action', 'data_access', 'tool_call'];
  let requestType = 'data_access';
  if (body.request_type !== undefined && body.request_type !== null) {
    if (typeof body.request_type !== 'string' || !VALID_REQUEST_TYPES.includes(body.request_type)) {
      return json(400, { error: `request_type must be one of: ${VALID_REQUEST_TYPES.join(', ')}.` });
    }
    requestType = body.request_type;
  }

  // 3. Delegate to the database: key auth, idempotency, and evaluation all
  //    happen inside a single transaction in ingest_api_event.
  const supabase = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false },
  });

  if (!HEX64_RE.test(keyHash)) {
    return json(500, { error: 'Server misconfigured' });
  }

  const { data, error } = await supabase.rpc('ingest_api_event', {
    p_key_hash: keyHash,
    p_event_id: eventId,
    p_ai_model_id: aiModelId,
    p_model_name: modelName,
    p_purpose: purpose,
    p_data_asset_ids: assetIds,
    p_agent_name: agentName,
    p_request_type: requestType,
  });

  if (error) {
    const message = error.message ?? '';
    const code = (error as { code?: string }).code ?? '';
    // 28000 = invalid key (deliberately vague). Everything else is a caller
    // error only when we recognize the message; never leak internals.
    if (code === '28000' || /invalid api key/i.test(message)) {
      return json(401, { error: 'Invalid API key' });
    }
    if (
      /event_id is required|ai_model_id or model_name|ai model not found|ai agent not found/i.test(
        message,
      )
    ) {
      return json(400, { error: message });
    }
    console.error('ingest_api_event failed:', message);
    return json(500, { error: 'Evaluation failed' });
  }

  return json(200, data as Record<string, unknown>);
});
