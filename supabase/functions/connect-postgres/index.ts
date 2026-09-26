// supabase/functions/connect-postgres/index.ts
//
// Connects a real PostgreSQL database as a Data Control Plane data source.
//
// - Validates the caller's JWT (Supabase Auth) and requires an
//   owner/admin/security role in the organization (RLS enforces this too).
// - Tests the connection over TLS with a short timeout, then saves ONLY the
//   non-secret connection details (host, port, database, username) on the
//   data_sources row. The password is used once, in memory, and is never
//   stored, logged, or returned.
// - Column discovery runs separately via the discover-postgres function.
//
// Deploy: supabase functions deploy connect-postgres

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import { Client } from 'https://deno.land/x/postgres@v0.17.0/mod.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

interface ConnectPayload {
  organization_id: string;
  name: string;
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HOST_RE = /^[a-zA-Z0-9.-]{1,253}$/;
const IDENT_RE = /^[a-zA-Z0-9_-]{1,63}$/;
const CONNECT_TIMEOUT_MS = 15000;

function badRequest(message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 400,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

function validate(body: ConnectPayload): string | null {
  if (!body.organization_id || !UUID_RE.test(body.organization_id)) {
    return 'organization_id must be a UUID.';
  }
  if (!body.name || typeof body.name !== 'string' || body.name.trim().length === 0 || body.name.length > 80) {
    return 'name is required (max 80 chars).';
  }
  if (!body.host || typeof body.host !== 'string' || !HOST_RE.test(body.host)) {
    return 'host must be a valid hostname or IP address.';
  }
  if (!Number.isInteger(body.port) || body.port < 1 || body.port > 65535) {
    return 'port must be an integer between 1 and 65535.';
  }
  if (!body.database || typeof body.database !== 'string' || !IDENT_RE.test(body.database)) {
    return 'database must be a valid database name.';
  }
  if (!body.username || typeof body.username !== 'string' || !IDENT_RE.test(body.username)) {
    return 'username must be a valid database username.';
  }
  if (!body.password || typeof body.password !== 'string' || body.password.length === 0 || body.password.length > 500) {
    return 'password is required.';
  }
  return null;
}

/** Opens a TLS connection, runs a trivial query, then closes it. Never logs the password. */
async function testConnection(cfg: {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
}): Promise<void> {
  const client = new Client({
    hostname: cfg.host,
    port: cfg.port,
    database: cfg.database,
    user: cfg.username,
    password: cfg.password,
    tls: { enabled: true, enforce: false },
    connection: { attempts: 1 },
  });
  let timer: number | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('Connection timed out.')), CONNECT_TIMEOUT_MS);
    });
    await Promise.race([
      (async () => {
        await client.connect();
        await client.queryObject('select 1');
      })(),
      timeout,
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    await client.end().catch(() => {});
  }
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
  let body: ConnectPayload;
  try {
    body = await req.json();
  } catch {
    return badRequest('Request body must be valid JSON.');
  }
  const validationError = validate(body);
  if (validationError) return badRequest(validationError);

  const { organization_id, name, host, port, database, username, password } = body;

  // 3. Connecting a database is privileged: owner, admin, or security only.
  const { data: privileged, error: roleError } = await supabase.rpc('has_org_role', {
    org_id: organization_id,
    allowed: ['owner', 'admin', 'security'],
  });
  if (roleError || !privileged) {
    return new Response(
      JSON.stringify({ error: 'Connecting a database requires the owner, admin, or security role.' }),
      { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  }

  // 4. Test the connection before saving anything.
  try {
    await testConnection({ host, port, database, username, password });
  } catch (err) {
    const detail = err instanceof Error ? err.message : 'unknown error';
    return new Response(
      JSON.stringify({
        error: `Could not connect to ${host}:${port}/${database} (${detail}). Check the host, port, and credentials, and use a read-only database user.`,
      }),
      { status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  }

  // 5. Save the source. Only non-secret config is persisted; the password
  //    stays in memory for this request and is never stored.
  const { data: source, error: insertError } = await supabase
    .from('data_sources')
    .insert({
      organization_id,
      name: name.trim(),
      type: 'postgresql',
      status: 'connected',
      description: `PostgreSQL at ${host}:${port}/${database}`,
      metadata: { host, port, database, username, discovered: false },
    })
    .select('id,name,type,status,description,metadata,last_scan_at')
    .single();

  if (insertError) {
    return new Response(JSON.stringify({ error: 'Could not save the data source.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  return new Response(
    JSON.stringify({
      source: {
        id: source.id,
        name: source.name,
        type: source.type,
        status: source.status,
        host,
        port,
        database,
        username,
      },
      message: 'Connected. Run discovery to import its tables into your catalog.',
    }),
    { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
  );
});
