-- 030_agent_guardrails.sql
-- Phase G — agent guardrails: per-agent tool policies, call/volume limits,
-- loop detection, and privilege-escalation signals.
--
-- ai_agents gains:
--   allowed_tools: empty = unrestricted (backward compatible); non-empty =
--     the agent may only call these tools.
--   blocked_tools: denylist, checked first, always wins.
--   approval_required_for: tool names (or '*') that always need approval
--     for this agent, even when the MCP risk policy would allow them.
--   max_tool_calls_per_hour / max_data_bytes_per_hour: rolling-hour caps
--     (null = unlimited).
--   max_consecutive_identical_calls: loop threshold (default 5 — the 6th
--     identical call in a row is blocked).
--
-- agent_tool_calls logs every guarded tool invocation (by the agent) with a
-- SHA-256 hash of the canonicalized arguments — loop detection without
-- storing argument payloads twice.
--
-- check_agent_guardrails() is the single enforcement point, called by
-- mcp-gateway before the MCP pipeline runs. It fails closed (block) and
-- writes a risk event for anomaly-class violations: privilege-escalation
-- signals (blocked tool, allowlist breach, tool risk above the agent's own
-- risk level) and runaway loops. Plain limit hits block without a risk
-- event — they are policy enforcement, not compromise signals.

alter table public.ai_agents
  add column allowed_tools text[] not null default '{}',
  add column blocked_tools text[] not null default '{}',
  add column approval_required_for text[] not null default '{}',
  add column max_tool_calls_per_hour integer
    check (max_tool_calls_per_hour is null or max_tool_calls_per_hour > 0),
  add column max_data_bytes_per_hour bigint
    check (max_data_bytes_per_hour is null or max_data_bytes_per_hour > 0),
  add column max_consecutive_identical_calls integer not null default 5
    check (max_consecutive_identical_calls >= 2);

create table public.agent_tool_calls (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  agent_id uuid not null references public.ai_agents(id) on delete cascade,
  mcp_tool_call_id uuid references public.mcp_tool_calls(id) on delete set null,
  tool_name text not null,
  -- SHA-256 of the canonicalized arguments: loop detection without storing
  -- the payload twice (the payload lives on the mcp_tool_call row).
  arguments_hash text not null,
  args_bytes integer not null default 0,
  result_bytes integer not null default 0,
  decision text not null check (decision in ('allowed', 'require_approval', 'blocked')),
  created_at timestamptz not null default now()
);

create index agent_tool_calls_agent_time_idx
  on public.agent_tool_calls (agent_id, created_at desc);
create index agent_tool_calls_org_idx
  on public.agent_tool_calls (organization_id);

-- Risk rank helper (low < medium < high < critical).
create or replace function public.agent_risk_rank(level text)
returns integer
language sql
immutable
set search_path = public
as $$
  select case level
    when 'low' then 0
    when 'medium' then 1
    when 'high' then 2
    when 'critical' then 3
    else -1
  end;
$$;

-- The single enforcement point for agent tool-use policy.
-- Returns { decision: 'allow'|'require_approval'|'block',
--           force_approval: bool, reasons: text[], escalation: bool }.
-- Service-role only: the gateways call it after authenticating the caller.
create or replace function public.check_agent_guardrails(
  p_organization_id uuid,
  p_agent_id uuid,
  p_tool_name text,
  p_tool_risk text,
  p_args_hash text,
  p_args_bytes integer
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_agent public.ai_agents%rowtype;
  v_decision text := 'allow';
  v_force_approval boolean := false;
  v_reasons text[] := '{}';
  v_escalation boolean := false;
  v_count integer;
  v_volume bigint;
  v_consecutive integer := 0;
  v_threshold integer;
  v_row record;
begin
  select * into v_agent
  from public.ai_agents
  where id = p_agent_id and organization_id = p_organization_id;
  if not found then
    raise exception 'ai agent not found in organization';
  end if;

  -- 1. Only active agents act.
  if v_agent.status <> 'active' then
    return jsonb_build_object(
      'decision', 'block',
      'force_approval', false,
      'reasons', jsonb_build_array('agent is ' || v_agent.status),
      'escalation', false
    );
  end if;

  -- 2. Blocked tools: deny wins. Probing a blocked tool is a
  --    privilege-escalation signal.
  if p_tool_name = any (v_agent.blocked_tools) then
    v_decision := 'block';
    v_reasons := v_reasons || ARRAY['tool is blocked for this agent'];
    v_escalation := true;
  -- 3. Allowlist (when configured): anything unlisted is denied, and trying
  --    it is an escalation signal.
  elsif cardinality(v_agent.allowed_tools) > 0
    and not (p_tool_name = any (v_agent.allowed_tools)) then
    v_decision := 'block';
    v_reasons := v_reasons || ARRAY['tool is not in the agent''s allowlist'];
    v_escalation := true;
  -- 4. A tool must not outrank its agent: a low-risk agent reaching for a
  --    critical-risk tool is a privilege-escalation signal.
  elsif public.agent_risk_rank(p_tool_risk) > public.agent_risk_rank(v_agent.risk_level) then
    v_decision := 'block';
    v_reasons := v_reasons || ARRAY[('tool risk (' || p_tool_risk || ') exceeds agent risk (' || v_agent.risk_level || ')')];
    v_escalation := true;
  end if;

  -- 5. Rolling-hour call cap.
  if v_decision = 'allow' and v_agent.max_tool_calls_per_hour is not null then
    select count(*) into v_count
    from public.agent_tool_calls
    where agent_id = p_agent_id and created_at > now() - interval '1 hour';
    if v_count >= v_agent.max_tool_calls_per_hour then
      v_decision := 'block';
      v_reasons := v_reasons || ARRAY['hourly tool call limit exceeded'];
    end if;
  end if;

  -- 6. Rolling-hour data-volume cap (args + results so far, plus this call's args).
  if v_decision = 'allow' and v_agent.max_data_bytes_per_hour is not null then
    select coalesce(sum(args_bytes + result_bytes), 0) into v_volume
    from public.agent_tool_calls
    where agent_id = p_agent_id and created_at > now() - interval '1 hour';
    if v_volume + p_args_bytes > v_agent.max_data_bytes_per_hour then
      v_decision := 'block';
      v_reasons := v_reasons || ARRAY['hourly data volume limit exceeded'];
    end if;
  end if;

  -- 7. Loop detection: a trailing run of identical (tool, args) calls at the
  --    threshold means the next identical call is a runaway loop.
  if v_decision = 'allow' then
    v_threshold := v_agent.max_consecutive_identical_calls;
    for v_row in
      select tool_name, arguments_hash
      from public.agent_tool_calls
      where agent_id = p_agent_id
      order by created_at desc, id desc
      limit v_threshold + 1
    loop
      if v_row.tool_name = p_tool_name and v_row.arguments_hash = p_args_hash then
        v_consecutive := v_consecutive + 1;
      else
        exit;
      end if;
    end loop;
    if v_consecutive >= v_threshold then
      v_decision := 'block';
      v_reasons := v_reasons || ARRAY[('loop detected: ' || (v_consecutive + 1) || ' identical calls in a row')];
      v_escalation := true;
    end if;
  end if;

  -- 8. Per-agent approval requirements (only when nothing blocked).
  if v_decision = 'allow'
    and ('*' = any (v_agent.approval_required_for) or p_tool_name = any (v_agent.approval_required_for)) then
    v_force_approval := true;
    v_reasons := v_reasons || ARRAY['agent policy requires approval for this tool'];
  end if;

  -- 9. Anomaly-class violations create a security event. Plain limit hits do
  --    not — they are policy enforcement, not compromise signals.
  if v_decision = 'block' and v_escalation then
    insert into public.risk_events
      (organization_id, ai_agent_id, title, description, severity, recommended_action, metadata)
    values (
      p_organization_id,
      p_agent_id,
      'Agent guardrail violation: ' || p_tool_name,
      array_to_string(v_reasons, '; '),
      'high',
      'Review the agent''s recent tool calls for compromise or misconfiguration.',
      jsonb_build_object(
        'tool_name', p_tool_name,
        'tool_risk', p_tool_risk,
        'reasons', to_jsonb(v_reasons),
        'guardrail', 'agent-v1'
      )
    );
  end if;

  return jsonb_build_object(
    'decision', v_decision,
    'force_approval', v_force_approval,
    'reasons', to_jsonb(v_reasons),
    'escalation', v_escalation
  );
end;
$$;

-- RLS ---------------------------------------------------------------------------
alter table public.agent_tool_calls enable row level security;

-- Members read their org's agent activity (transparency); lifecycle writes go
-- through the gateways as service_role, so no member write policies.
create policy agent_tool_calls_select on public.agent_tool_calls
  for select using (public.is_org_member(organization_id));

-- The guardrail check is service-role only: the gateways authenticate the
-- caller first, then call it. Never expose it to anon/authenticated directly.
revoke execute on function public.check_agent_guardrails(uuid, uuid, text, text, text, integer)
  from public, anon;
revoke execute on function public.agent_risk_rank(text) from public, anon;
grant execute on function public.agent_risk_rank(text) to authenticated;
