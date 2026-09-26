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
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function badRequest(message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 400,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

serve(async (req: Request): Promise<Response> => {
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

  // 3. Run the secure database logic with the caller's identity.
  const { data, error } = await supabase.rpc('evaluate_ai_request', {
    p_organization_id: organization_id,
    p_ai_model_id: ai_model_id,
    p_purpose: purpose,
    p_data_asset_ids: data_asset_ids,
    p_user_id: user_id,
    p_agent_id: agent_id,
    p_request_type: request_type,
  });

  if (error) {
    const status = error.code === '42501' ? 403 : 500;
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
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
});
