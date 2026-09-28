// supabase/functions/monitoring-check/index.ts
//
// Periodic monitoring sweep: evaluates every active alert_rule against the
// function_metrics recorded by _shared/metrics.ts (via the
// record_function_metric RPC from migration 022_monitoring.sql) and fires or
// resolves alerts through the public.check_alert_rule SQL function.
//
// Deploy: supabase functions deploy monitoring-check
// Schedule: call this endpoint on a cron (e.g. every 5 minutes). If
//   MONITORING_CRON_SECRET is set, the caller must send
//   Authorization: Bearer <secret> — set this secret so the sweep cannot be
//   triggered by the public. If it is unset, the endpoint is open; only rely
//   on that behind a restricted cron (e.g. pg_cron calling with the service
//   role key) — never expose it publicly without the secret.
//
// Response: { checked, fired: [rule ids], resolved: [rule ids] }

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
};

function json(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

serve(async (req: Request): Promise<Response> => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }
  if (req.method !== 'POST' && req.method !== 'GET') {
    return json(405, { error: 'Method not allowed' });
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !serviceKey) {
    return json(500, { error: 'Server misconfigured' });
  }

  // Optional shared-secret guard for cron callers. When MONITORING_CRON_SECRET
  // is unset the endpoint accepts any caller — see the header comment above.
  const cronSecret = Deno.env.get('MONITORING_CRON_SECRET');
  if (cronSecret) {
    const authHeader = req.headers.get('Authorization') ?? '';
    if (authHeader !== `Bearer ${cronSecret}`) {
      return json(401, { error: 'Unauthorized' });
    }
  }

  const supabase = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: rules, error: rulesError } = await supabase
    .from('alert_rules')
    .select('id')
    .eq('is_active', true);

  if (rulesError) {
    return json(500, { error: 'Could not load alert rules' });
  }

  const fired: string[] = [];
  const resolved: string[] = [];

  for (const rule of rules ?? []) {
    const { data, error } = await supabase.rpc('check_alert_rule', {
      p_rule_id: rule.id,
    });
    if (error) {
      // One bad rule must not abort the whole sweep.
      console.error(`check_alert_rule failed for ${rule.id}: ${error.message}`);
      continue;
    }
    const result = data as { fired?: boolean; resolved?: boolean } | null;
    if (result?.fired) fired.push(rule.id);
    if (result?.resolved) resolved.push(rule.id);
  }

  return json(200, { checked: rules?.length ?? 0, fired, resolved });
});
