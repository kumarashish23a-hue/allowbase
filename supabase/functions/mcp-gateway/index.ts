// supabase/functions/mcp-gateway/index.ts
//
// Phase F — the MCP security gateway: the enforcement point in front of
// Model Context Protocol servers.
//
// Every tool call goes through the pipeline, server-side:
//   1. Authenticate: Supabase user session (JWT) + org membership. Phase F
//      is JWT-only; machine-key access is a documented follow-up.
//   2. Validate the action: 'call' (default) starts a new invocation;
//      'execute' resumes a held-for-approval call after a human approves it.
//   3. Load the server (must belong to the org and be active) and the tool.
//   4. Inspect the ARGUMENTS for attack patterns and secrets (in memory;
//      raw values never stored — counts by category only).
//   5. Policy: dangerous operations default to APPROVAL — a dangerous verb
//      in the tool name/description (delete, drop, export, transfer,
//      execute), a high/critical risk level, an explicit requires_approval
//      flag, or secrets/oversized arguments all hold the call. High/critical
//      attack patterns in arguments BLOCK it outright.
//   6. On approval: the call waits as pending_approval with a linked
//      approval_requests row (24h expiry, owner/admin decide, expired rows
//      fail the call closed). 'execute' resumes it after approval.
//   7. Execution: MCP JSON-RPC 2.0 tools/call over HTTP POST to the server's
//      SSRF-checked base URL, 30s timeout. The server's OUTPUT is inspected:
//      sensitive spans are masked before the result reaches the caller, and
//      critical attack patterns in tool output are flagged in the audit
//      trail (detective — the tool already ran).
//
// Tool results are returned to the caller but only a masked <=2KB preview is
// stored. Audit rows carry decisions and finding counts, never raw argument
// or output values.
//
// Phase G — agent guardrails: an optional agent_id on 'call' (and re-checked
// on 'execute') runs the call through public.check_agent_guardrails first —
// allowlist/blocklist, tool-risk vs agent-risk, per-agent approval lists,
// hourly call/volume caps, and loop detection. Guardrail blocks are terminal
// and anomaly-class violations (escalation signals, loops) create risk
// events. Every guarded invocation is logged to agent_tool_calls with a
// SHA-256 hash of the arguments (not the payload twice).

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import type { SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import {
  classifyToolRisk,
  toolRequiresApproval,
  inspectToolArguments,
  buildJsonRpcCall,
  summarizeToolResult,
  MCP_VERSION,
  type McpDecision,
  type McpRiskLevel,
} from '../_shared/mcp.ts';
import { checkEndpointRateLimit, rateLimitedResponse } from '../_shared/rateLimit.ts';
import { recordMetric, nowMs } from '../_shared/metrics.ts';
import { isSafeProviderUrlAsync } from '../_shared/ssrf.ts';
import {
  hashArguments,
  parseGuardVerdict,
  guardForcesApproval,
  AGENT_GUARD_VERSION,
  type GuardVerdict,
} from '../_shared/agentGuard.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-api-key',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TOOL_CALL_TIMEOUT_MS = 30000;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

function validate(body: Record<string, unknown>): string | null {
  const action = body.action === undefined ? 'call' : body.action;
  if (action !== 'call' && action !== 'execute') return "action must be 'call' or 'execute'.";
  if (typeof body.organization_id !== 'string' || !UUID_RE.test(body.organization_id)) {
    return 'organization_id must be a UUID.';
  }
  if (action === 'call') {
    if (typeof body.server_id !== 'string' || !UUID_RE.test(body.server_id)) return 'server_id must be a UUID.';
    if (typeof body.tool_name !== 'string' || body.tool_name.length === 0 || body.tool_name.length > 200) {
      return 'tool_name must be a non-empty string (max 200 chars).';
    }
    if (body.arguments !== undefined && (typeof body.arguments !== 'object' || body.arguments === null || Array.isArray(body.arguments))) {
      return 'arguments must be a JSON object.';
    }
    if (body.agent_id !== undefined && body.agent_id !== null && (typeof body.agent_id !== 'string' || !UUID_RE.test(body.agent_id))) {
      return 'agent_id must be a UUID or null.';
    }
  } else {
    if (typeof body.tool_call_id !== 'string' || !UUID_RE.test(body.tool_call_id)) {
      return 'tool_call_id must be a UUID.';
    }
  }
  return null;
}

interface McpServer {
  id: string;
  organization_id: string;
  name: string;
  base_url: string | null;
  status: string;
}

interface McpTool {
  id: string;
  name: string;
  description: string | null;
  risk_level: McpRiskLevel;
  requires_approval: boolean;
}

interface McpToolCall {
  id: string;
  organization_id: string;
  server_id: string;
  tool_id: string | null;
  tool_name: string;
  arguments: Record<string, unknown>;
  requested_by: string | null;
  status: string;
  risk_level: McpRiskLevel;
  approval_id: string | null;
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

  const action = (body.action as string | undefined) ?? 'call';
  const organization_id = body.organization_id as string;

  // 1. Authenticate: JWT + active membership (any role may request tools;
  //    what RUNS is governed by the risk policy + approvals).
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
  const { data: isMember, error: memberError } = await userClient.rpc('is_org_member', {
    org_id: organization_id,
  });
  if (memberError || !isMember) return json({ error: 'Not a member of this organization.' }, 403);

  const meter = (status: 'ok' | 'error' | 'rate_limited', errorCode?: string | null) =>
    recordMetric(admin, {
      functionName: 'mcp-gateway',
      organizationId: organization_id,
      status,
      latencyMs: nowMs() - t0,
      errorCode: errorCode ?? null,
    });

  const rateLimit = await checkEndpointRateLimit(admin, 'mcp-gateway', organization_id);
  if (!rateLimit.allowed) {
    meter('rate_limited');
    return rateLimitedResponse(rateLimit.retryAfter, corsHeaders);
  }

  async function audit(toolCallId: string | null, act: string, result: string, metadata: Record<string, unknown>) {
    try {
      await admin.from('audit_logs').insert({
        organization_id,
        actor_user_id: user!.id,
        actor_type: 'user',
        action: act,
        resource_type: 'mcp_tool_call',
        resource_id: toolCallId,
        result,
        metadata: { mcp_version: MCP_VERSION, ...metadata },
      });
    } catch {
      /* audit is best-effort */
    }
  }

  /** Execute one approved/allowed call against its MCP server.
   *  agentCtx links this execution to a guarded agent invocation so the
   *  result size lands on the right agent_tool_calls row. */
  async function executeCall(
    call: McpToolCall,
    server: McpServer,
    agentCtx?: { agentToolCallId: string },
  ): Promise<Response> {
    if (!server.base_url) {
      await admin.from('mcp_tool_calls').update({ status: 'failed', error: 'Server has no base URL configured.' }).eq('id', call.id);
      meter('ok', 'no_base_url');
      return json({ error: 'The MCP server has no base URL configured.' }, 400);
    }
    if (!(await isSafeProviderUrlAsync(server.base_url))) {
      await admin.from('mcp_tool_calls').update({ status: 'blocked', decision: 'blocked', decision_reason: 'server URL failed the safety check' }).eq('id', call.id);
      await audit(call.id, 'mcp_tool_blocked', 'blocked', { reason: 'unsafe_server_url', tool_name: call.tool_name });
      meter('ok', 'unsafe_server_url');
      return json({ error: 'The MCP server URL failed the safety check.' }, 400);
    }

    await admin.from('mcp_tool_calls').update({ status: 'executing' }).eq('id', call.id);

    let result: unknown;
    try {
      const res = await fetch(server.base_url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(buildJsonRpcCall(call.id, call.tool_name, call.arguments)),
        signal: AbortSignal.timeout(TOOL_CALL_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`MCP server returned ${res.status}.`);
      const data = (await res.json()) as { result?: unknown; error?: { message?: string } };
      if (data.error) throw new Error('The MCP server reported an error.');
      result = data.result ?? null;
    } catch {
      await admin
        .from('mcp_tool_calls')
        .update({ status: 'failed', error: 'The MCP server call failed.' })
        .eq('id', call.id);
      await audit(call.id, 'mcp_tool_executed', 'failed', { tool_name: call.tool_name });
      meter('error', 'execution_error');
      // Status line only — never leak server internals or the URL.
      return json({ error: 'The MCP server call failed.', tool_call_id: call.id }, 502);
    }

    // 7. Output inspection: mask sensitive spans, flag critical threats.
    const summary = summarizeToolResult(result);
    const { data: existing } = await admin
      .from('mcp_tool_calls')
      .select('finding_counts')
      .eq('id', call.id)
      .maybeSingle();
    const priorCounts = ((existing as { finding_counts?: Record<string, unknown> } | null)?.finding_counts ?? {}) as Record<
      string,
      unknown
    >;
    await admin
      .from('mcp_tool_calls')
      .update({
        status: 'succeeded',
        result_preview: summary.preview,
        finding_counts: {
          ...priorCounts,
          output_sensitive: summary.sensitiveCounts,
          output_threats: summary.threatCounts,
          output_masked: summary.maskedCount,
        },
      })
      .eq('id', call.id);
    await audit(call.id, 'mcp_tool_executed', 'succeeded', {
      tool_name: call.tool_name,
      risk_level: call.risk_level,
      result_masked: summary.masked,
      output_threat_critical: summary.threatCritical,
      finding_counts: { output_sensitive: summary.sensitiveCounts, output_threats: summary.threatCounts },
    });

    meter('ok');
    // Guarded agents: record the result size for hourly volume accounting.
    if (agentCtx) {
      try {
        const resultBytes = new TextEncoder().encode(JSON.stringify(result)).length;
        await admin.from('agent_tool_calls').update({ result_bytes: resultBytes }).eq('id', agentCtx.agentToolCallId);
      } catch {
        /* volume accounting is best-effort */
      }
    }
    return json({
      tool_call_id: call.id,
      status: 'succeeded',
      // When masking applied the caller gets the masked preview string;
      // otherwise the server's parsed result. result_masked says which.
      result: summary.masked ? summary.preview : result,
      result_masked: summary.masked,
      output_threat_critical: summary.threatCritical,
    });
  }

  // --- Phase G helpers -------------------------------------------------------
  /** Log one guarded agent invocation. Returns the agent_tool_calls id. */
  async function logAgentCall(
    agentId: string,
    toolCallId: string | null,
    toolName: string,
    argsHash: string,
    argsBytes: number,
    decision: 'allowed' | 'require_approval' | 'blocked',
  ): Promise<string | null> {
    try {
      const { data } = await admin
        .from('agent_tool_calls')
        .insert({
          organization_id,
          agent_id: agentId,
          mcp_tool_call_id: toolCallId,
          tool_name: toolName,
          arguments_hash: argsHash,
          args_bytes: argsBytes,
          decision,
        })
        .select('id')
        .single();
      return (data as { id: string } | null)?.id ?? null;
    } catch {
      return null;
    }
  }

  /** Run the agent guardrail check. Returns null when no agent is involved. */
  async function checkAgentGuardrails(
    agentId: string | null,
    toolName: string,
    risk: McpRiskLevel,
    args: Record<string, unknown>,
  ): Promise<{ verdict: GuardVerdict; argsHash: string; argsBytes: number } | null> {
    if (!agentId) return null;
    const argsHash = await hashArguments(args);
    const argsBytes = new TextEncoder().encode(JSON.stringify(args)).length;
    const { data, error } = await admin.rpc('check_agent_guardrails', {
      p_organization_id: organization_id,
      p_agent_id: agentId,
      p_tool_name: toolName,
      p_tool_risk: risk,
      p_args_hash: argsHash,
      p_args_bytes: argsBytes,
    });
    if (error) {
      // Fail closed: an unenforceable guardrail denies the call.
      return {
        verdict: { decision: 'block', forceApproval: false, reasons: ['agent guardrail check failed'], escalation: false },
        argsHash,
        argsBytes,
      };
    }
    return { verdict: parseGuardVerdict(data), argsHash, argsBytes };
  }

  // --- action: execute (resume a held-for-approval call) -----------------------
  if (action === 'execute') {
    const tool_call_id = body.tool_call_id as string;
    const { data: call, error: callError } = await admin
      .from('mcp_tool_calls')
      .select('id,organization_id,server_id,tool_id,tool_name,arguments,requested_by,status,risk_level,approval_id')
      .eq('id', tool_call_id)
      .eq('organization_id', organization_id)
      .maybeSingle();
    if (callError || !call) {
      meter('ok', 'call_not_found');
      return json({ error: 'Tool call not found.' }, 404);
    }
    const c = call as McpToolCall;
    if (!['pending_approval', 'approved'].includes(c.status)) {
      meter('ok', 'call_not_executable');
      return json({ error: `Tool call is ${c.status}; only approved calls can execute.` }, 409);
    }
    // The approval must exist and be approved — never execute on pending,
    // rejected, or expired. Lazy-expiry sweep first (no pg_cron).
    await admin.rpc('expire_stale_approvals');
    const { data: approval } = await admin
      .from('approval_requests')
      .select('id,status')
      .eq('mcp_tool_call_id', c.id)
      .maybeSingle();
    if (!approval || (approval as { status: string }).status !== 'approved') {
      meter('ok', 'not_approved');
      const st = (approval as { status: string } | null)?.status;
      return json(
        { error: st === 'pending' ? 'The approval is still pending.' : 'The tool call was not approved.' },
        st === 'pending' ? 409 : 403,
      );
    }
    const { data: server } = await admin
      .from('mcp_servers')
      .select('id,organization_id,name,base_url,status')
      .eq('id', c.server_id)
      .maybeSingle();
    if (!server || (server as McpServer).status !== 'active') {
      meter('ok', 'server_inactive');
      return json({ error: 'The MCP server is no longer active.' }, 400);
    }
    // Phase G: re-check agent guardrails at execute time — limits and loop
    // state may have changed while the approval was pending.
    let agentCtx: { agentToolCallId: string } | undefined;
    const { data: priorAgentCall } = await admin
      .from('agent_tool_calls')
      .select('id,agent_id,tool_name,arguments_hash,args_bytes')
      .eq('mcp_tool_call_id', c.id)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (priorAgentCall) {
      const pac = priorAgentCall as { id: string; agent_id: string; tool_name: string; arguments_hash: string; args_bytes: number };
      const { data: guardData, error: guardError } = await admin.rpc('check_agent_guardrails', {
        p_organization_id: organization_id,
        p_agent_id: pac.agent_id,
        p_tool_name: pac.tool_name,
        p_tool_risk: c.risk_level,
        p_args_hash: pac.arguments_hash,
        p_args_bytes: pac.args_bytes,
      });
      let verdict = guardError
        ? { decision: 'block' as const, forceApproval: false, reasons: ['agent guardrail check failed'], escalation: false }
        : parseGuardVerdict(guardData);
      if (verdict.decision === 'block') {
        await logAgentCall(pac.agent_id, c.id, pac.tool_name, pac.arguments_hash, pac.args_bytes, 'blocked');
        await audit(c.id, 'mcp_tool_blocked', 'blocked', {
          tool_name: pac.tool_name,
          agent_id: pac.agent_id,
          reasons: verdict.reasons,
          guardrail: AGENT_GUARD_VERSION,
        });
        meter('ok', 'agent_guardrail_block');
        return json({ error: 'The tool call was blocked by agent guardrails.', reasons: verdict.reasons }, 403);
      }
      // No new row: this is the same logical call the approval was granted
      // for — the call-time row already counts against hourly limits. The
      // execution result size lands on that row.
      agentCtx = { agentToolCallId: pac.id };
    }
    return executeCall(c, server as McpServer, agentCtx);
  }

  // --- action: call (new invocation) -------------------------------------------
  const server_id = body.server_id as string;
  const tool_name = body.tool_name as string;
  const args = (body.arguments as Record<string, unknown> | undefined) ?? {};

  const { data: server, error: serverError } = await admin
    .from('mcp_servers')
    .select('id,organization_id,name,base_url,status')
    .eq('id', server_id)
    .eq('organization_id', organization_id)
    .maybeSingle();
  if (serverError || !server) {
    meter('ok', 'server_not_found');
    return json({ error: 'MCP server not found.' }, 404);
  }
  const s = server as McpServer;
  if (s.status !== 'active') {
    meter('ok', 'server_paused');
    return json({ error: 'The MCP server is paused.' }, 400);
  }

  const { data: tool } = await admin
    .from('mcp_tools')
    .select('id,name,description,risk_level,requires_approval')
    .eq('server_id', s.id)
    .eq('name', tool_name)
    .maybeSingle();
  if (!tool) {
    meter('ok', 'tool_not_found');
    return json({ error: 'Tool not found on this server.' }, 404);
  }
  const t = tool as McpTool;
  // The declared level can only raise, never lower, the computed risk.
  const risk = classifyToolRisk(t.name, t.description, t.risk_level);

  // Phase G: agent guardrails run before argument inspection — who/what is
  // governed first, content second. A guardrail block is terminal.
  const agentId = (body.agent_id as string | null | undefined) ?? null;
  const guard = await checkAgentGuardrails(agentId, t.name, risk, args);
  if (guard && guard.verdict.decision === 'block') {
    const { data: guardBlockedCall } = await admin
      .from('mcp_tool_calls')
      .insert({
        organization_id,
        server_id: s.id,
        tool_id: t.id,
        tool_name: t.name,
        arguments: args,
        requested_by: user.id,
        status: 'blocked',
        risk_level: risk,
        decision: 'blocked',
        decision_reason: guard.verdict.reasons.join('; '),
        finding_counts: {},
      })
      .select('id')
      .single();
    const guardBlockedId = (guardBlockedCall as { id: string } | null)?.id ?? null;
    const agentLogId = await logAgentCall(agentId!, guardBlockedId, t.name, guard.argsHash, guard.argsBytes, 'blocked');
    await audit(guardBlockedId, 'mcp_tool_blocked', 'blocked', {
      tool_name: t.name,
      risk_level: risk,
      agent_id: agentId,
      agent_tool_call_id: agentLogId,
      reasons: guard.verdict.reasons,
      guardrail: AGENT_GUARD_VERSION,
    });
    meter('ok', 'agent_guardrail_block');
    return json({ error: 'The tool call was blocked by agent guardrails.', tool_call_id: guardBlockedId, reasons: guard.verdict.reasons }, 403);
  }

  // 4+5. Inspect arguments, then decide: block | require_approval | allowed.
  const argInspection = inspectToolArguments(args);
  let decision: McpDecision = 'allowed';
  const reasons: string[] = [];
  if (guard && guardForcesApproval(guard.verdict)) {
    // Per-agent approval requirements upgrade an allowed call to held —
    // they never downgrade a block or bypass argument inspection below.
    decision = 'require_approval';
    reasons.push(...guard.verdict.reasons);
  }
  if (argInspection.decision === 'blocked') {
    decision = 'blocked';
    reasons.push(...argInspection.reasons);
  } else if (toolRequiresApproval({ name: t.name, description: t.description, risk_level: risk, requires_approval: t.requires_approval })) {
    decision = 'require_approval';
    reasons.push('dangerous operation requires approval');
  } else if (argInspection.decision === 'require_approval') {
    decision = 'require_approval';
    reasons.push(...argInspection.reasons);
  }

  const findingCounts = {
    arg_threats: argInspection.threatCounts,
    arg_sensitive: argInspection.sensitiveCounts,
  };

  // Blocked: terminal, never executed, never approvable.
  if (decision === 'blocked') {
    const { data: blockedCall } = await admin
      .from('mcp_tool_calls')
      .insert({
        organization_id,
        server_id: s.id,
        tool_id: t.id,
        tool_name: t.name,
        arguments: args,
        requested_by: user.id,
        status: 'blocked',
        risk_level: risk,
        decision,
        decision_reason: reasons.join('; '),
        finding_counts: findingCounts,
      })
      .select('id')
      .single();
    const blockedId = (blockedCall as { id: string } | null)?.id ?? null;
    const blockedAgentLogId = agentId && guard
      ? await logAgentCall(agentId, blockedId, t.name, guard.argsHash, guard.argsBytes, 'blocked')
      : null;
    await audit(blockedId, 'mcp_tool_blocked', 'blocked', {
      tool_name: t.name,
      risk_level: risk,
      reasons,
      agent_id: agentId,
      agent_tool_call_id: blockedAgentLogId,
      finding_counts: findingCounts,
    });
    meter('ok', 'blocked');
    return json({ error: 'The tool call was blocked by policy.', tool_call_id: blockedId, reasons }, 403);
  }

  // Held for approval: persist the call, open the approval, return 202.
  if (decision === 'require_approval') {
    const { data: heldCall, error: heldError } = await admin
      .from('mcp_tool_calls')
      .insert({
        organization_id,
        server_id: s.id,
        tool_id: t.id,
        tool_name: t.name,
        arguments: args,
        requested_by: user.id,
        status: 'pending_approval',
        risk_level: risk,
        decision,
        decision_reason: reasons.join('; '),
        finding_counts: findingCounts,
      })
      .select('id')
      .single();
    if (heldError || !heldCall) {
      meter('error', 'call_insert_failed');
      return json({ error: 'Could not record the tool call.' }, 500);
    }
    const heldId = (heldCall as { id: string }).id;
    // Approval expiry: 24h default, same as AI-request approvals (Phase B).
    const { data: approval, error: approvalError } = await admin
      .from('approval_requests')
      .insert({
        organization_id,
        mcp_tool_call_id: heldId,
        requested_by: user.id,
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      })
      .select('id,expires_at')
      .single();
    if (approvalError || !approval) {
      await admin.from('mcp_tool_calls').delete().eq('id', heldId);
      meter('error', 'approval_insert_failed');
      return json({ error: 'Could not open the approval request.' }, 500);
    }
    await admin.from('mcp_tool_calls').update({ approval_id: (approval as { id: string }).id }).eq('id', heldId);
    const heldAgentLogId = agentId && guard
      ? await logAgentCall(agentId, heldId, t.name, guard.argsHash, guard.argsBytes, 'require_approval')
      : null;
    await audit(heldId, 'mcp_tool_held', 'pending_approval', {
      tool_name: t.name,
      risk_level: risk,
      reasons,
      agent_id: agentId,
      agent_tool_call_id: heldAgentLogId,
      approval_id: (approval as { id: string }).id,
      finding_counts: findingCounts,
    });
    meter('ok');
    return json(
      {
        tool_call_id: heldId,
        status: 'pending_approval',
        approval_id: (approval as { id: string }).id,
        expires_at: (approval as { expires_at: string }).expires_at,
        reasons,
        message: 'Held for approval. Call action=execute with the tool_call_id after it is approved.',
      },
      202,
    );
  }

  // Allowed: persist and execute immediately.
  const { data: newCall, error: newCallError } = await admin
    .from('mcp_tool_calls')
    .insert({
      organization_id,
      server_id: s.id,
      tool_id: t.id,
      tool_name: t.name,
      arguments: args,
      requested_by: user.id,
      status: 'executing',
      risk_level: risk,
      decision,
      decision_reason: 'allowed by MCP risk policy',
      finding_counts: findingCounts,
    })
    .select('id,organization_id,server_id,tool_id,tool_name,arguments,requested_by,status,risk_level,approval_id')
    .single();
  if (newCallError || !newCall) {
    meter('error', 'call_insert_failed');
    return json({ error: 'Could not record the tool call.' }, 500);
  }
  await audit((newCall as { id: string }).id, 'mcp_tool_call', 'allowed', {
    tool_name: t.name,
    risk_level: risk,
    agent_id: agentId,
    finding_counts: findingCounts,
  });
  const allowedAgentLogId = agentId && guard
    ? await logAgentCall(agentId, (newCall as { id: string }).id, t.name, guard.argsHash, guard.argsBytes, 'allowed')
    : null;
  return executeCall(
    newCall as McpToolCall,
    s,
    allowedAgentLogId ? { agentToolCallId: allowedAgentLogId } : undefined,
  );
});
