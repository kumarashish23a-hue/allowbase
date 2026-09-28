-- 029_mcp_security.sql
-- Phase F — MCP security: servers, tools, tool calls, approvals.
--
-- Model:
--   mcp_servers: an org's registered MCP servers (HTTP JSON-RPC in Phase F).
--   mcp_tools: the tools a server exposes, each with a declared risk_level
--     and an optional requires_approval override.
--   mcp_tool_calls: every invocation, with its full lifecycle:
--     pending_approval -> approved|rejected|expired -> executing ->
--     succeeded|failed, plus blocked (terminal, never executed).
--
-- Dangerous operations default to approval: tool names/descriptions matching
-- delete|drop|export|transfer|execute (or a high/critical risk_level, or an
-- explicit requires_approval flag) are held for approval instead of run.
-- Tool ARGUMENTS are inspected too: high/critical attack patterns block the
-- call; high/critical secrets in arguments hold it for approval (passing
-- credentials to tools is often legitimate, exfiltrating them is not).
--
-- Approvals reuse the existing approval_requests table, generalized here:
-- ai_request_id becomes nullable and mcp_tool_call_id is added, with a
-- check that exactly one subject is set. decide_approval and
-- expire_stale_approvals are recreated as deliberate supersets of the 026
-- versions (same signatures; only the subject-branching is new).

-- Tables ----------------------------------------------------------------------
create table public.mcp_servers (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  transport text not null default 'http' check (transport in ('http')),
  -- Phase F speaks MCP JSON-RPC over HTTP POST to this URL (SSRF-checked at
  -- call time, like custom AI providers).
  base_url text,
  status text not null default 'active' check (status in ('active', 'paused')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, name)
);

create table public.mcp_tools (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  server_id uuid not null references public.mcp_servers(id) on delete cascade,
  name text not null,
  description text,
  input_schema jsonb not null default '{}'::jsonb,
  risk_level text not null default 'medium'
    check (risk_level in ('low', 'medium', 'high', 'critical')),
  -- Explicit override: when true the tool always requires approval even if
  -- its name looks harmless.
  requires_approval boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (server_id, name)
);

create table public.mcp_tool_calls (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  server_id uuid not null references public.mcp_servers(id) on delete cascade,
  tool_id uuid references public.mcp_tools(id) on delete set null,
  tool_name text not null,
  arguments jsonb not null default '{}'::jsonb,
  requested_by uuid references auth.users(id) on delete set null,
  status text not null default 'pending_approval'
    check (status in (
      'pending_approval', 'approved', 'rejected',
      'executing', 'succeeded', 'failed',
      'blocked', 'expired'
    )),
  risk_level text not null check (risk_level in ('low', 'medium', 'high', 'critical')),
  -- The pipeline verdict: 'allowed' | 'require_approval' | 'blocked'.
  decision text check (decision in ('allowed', 'require_approval', 'blocked')),
  decision_reason text,
  approval_id uuid references public.approval_requests(id) on delete set null,
  -- Masked, truncated tool output (<= 2 KB). Finding counts live in
  -- finding_counts; raw matched values are never stored.
  result_preview text,
  finding_counts jsonb not null default '{}'::jsonb,
  error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index mcp_servers_org_idx on public.mcp_servers (organization_id);
create index mcp_tools_server_idx on public.mcp_tools (server_id);
create index mcp_tools_org_idx on public.mcp_tools (organization_id);
create index mcp_tool_calls_org_idx on public.mcp_tool_calls (organization_id);
create index mcp_tool_calls_org_status_idx on public.mcp_tool_calls (organization_id, status);

-- Generalize approval_requests: AI requests XOR MCP tool calls -----------------
alter table public.approval_requests
  alter column ai_request_id drop not null;

alter table public.approval_requests
  add column mcp_tool_call_id uuid references public.mcp_tool_calls(id) on delete cascade;

alter table public.approval_requests
  add constraint approval_requests_single_subject
  check ((ai_request_id is null) <> (mcp_tool_call_id is null));

create unique index approval_requests_mcp_tool_call_uniq
  on public.approval_requests (mcp_tool_call_id)
  where mcp_tool_call_id is not null;

-- expire_stale_approvals: superset of 026 — expired approvals now also fail
-- their linked MCP tool calls closed (pending_approval -> expired).
create or replace function public.expire_stale_approvals()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_count integer := 0;
begin
  -- Overdue pendings become 'expired'; their AI requests fail closed to
  -- 'blocked' and their MCP tool calls fail closed to 'expired' (the
  -- gateways only execute on an explicit approval, so an expired approval
  -- can never be honored as one).
  with expired as (
    update public.approval_requests
    set status = 'expired'
    where status = 'pending' and expires_at <= now()
    returning id, organization_id, ai_request_id, mcp_tool_call_id
  ),
  blocked as (
    update public.ai_requests r
    set status = 'blocked'
    from expired e
    where r.id = e.ai_request_id and r.status = 'pending_approval'
    returning r.id
  ),
  tools_expired as (
    update public.mcp_tool_calls t
    set status = 'expired'
    from expired e
    where t.id = e.mcp_tool_call_id and t.status = 'pending_approval'
    returning t.id
  ),
  audited as (
    insert into public.audit_logs
      (organization_id, actor_type, action, resource_type, resource_id, result, metadata)
    select
      organization_id, 'system', 'approval_expired', 'approval_request', id, 'expired',
      jsonb_build_object(
        'ai_request_id', ai_request_id,
        'mcp_tool_call_id', mcp_tool_call_id,
        'reason', 'no decision before expires_at'
      )
    from expired
    returning 1
  )
  select count(*) into v_count from expired;
  return v_count;
end;
$$;

-- decide_approval: superset of 026 — same signature and AI-request behavior;
-- MCP tool calls transition pending_approval -> approved|rejected.
create or replace function public.decide_approval(
  p_approval_id uuid,
  p_decision text,
  p_note text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_approval public.approval_requests;
  v_new_status text;
  v_subject_status text;
begin
  if p_decision not in ('approved', 'rejected') then
    raise exception 'decision must be approved or rejected';
  end if;

  -- Lazy expiry: no pg_cron, so every decision point sweeps first.
  perform public.expire_stale_approvals();

  select * into v_approval
  from public.approval_requests
  where id = p_approval_id;
  if not found then
    raise exception 'approval request not found';
  end if;
  if v_approval.status = 'expired' then
    raise exception 'approval request has expired';
  end if;
  if v_approval.status <> 'pending' then
    raise exception 'approval request is no longer pending';
  end if;
  -- Belt and braces: the sweep above already flipped overdue rows, but never
  -- approve a row whose deadline passed even if the sweep raced us.
  if v_approval.expires_at <= now() then
    raise exception 'approval request has expired';
  end if;

  if not public.has_org_role(v_approval.organization_id, array['owner', 'admin']) then
    raise exception 'only organization owners or admins can decide approvals' using errcode = '42501';
  end if;

  v_new_status := case p_decision when 'approved' then 'allowed' else 'blocked' end;
  -- AI requests use the allowed/blocked vocabulary; tool calls use their own
  -- lifecycle vocabulary (approved/rejected).
  v_subject_status := case
    when v_approval.ai_request_id is not null then v_new_status
    when p_decision = 'approved' then 'approved'
    else 'rejected'
  end;

  update public.approval_requests
  set status = p_decision,
      decided_by = auth.uid(),
      decided_at = now(),
      note = p_note
  where id = p_approval_id;

  if v_approval.ai_request_id is not null then
    update public.ai_requests
    set status = v_new_status
    where id = v_approval.ai_request_id;
  else
    update public.mcp_tool_calls
    set status = v_subject_status
    where id = v_approval.mcp_tool_call_id;
  end if;

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action,
    resource_type, resource_id, result, metadata
  )
  values (
    v_approval.organization_id,
    auth.uid(),
    'user',
    'approval_' || p_decision,
    'approval_request',
    p_approval_id,
    p_decision,
    jsonb_build_object(
      'ai_request_id', v_approval.ai_request_id,
      'mcp_tool_call_id', v_approval.mcp_tool_call_id,
      'note', p_note,
      'self_approved', v_approval.requested_by = auth.uid()
    )
  );

  return jsonb_build_object(
    'approval_id', p_approval_id,
    'decision', p_decision,
    'ai_request_id', v_approval.ai_request_id,
    'mcp_tool_call_id', v_approval.mcp_tool_call_id,
    'request_status', v_subject_status
  );
end;
$$;

-- RLS ---------------------------------------------------------------------------
alter table public.mcp_servers enable row level security;
alter table public.mcp_tools enable row level security;
alter table public.mcp_tool_calls enable row level security;

-- Servers/tools: members read; owner/admin/security manage.
create policy mcp_servers_select on public.mcp_servers
  for select using (public.is_org_member(organization_id));
create policy mcp_servers_insert on public.mcp_servers
  for insert with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));
create policy mcp_servers_update on public.mcp_servers
  for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));
create policy mcp_servers_delete on public.mcp_servers
  for delete using (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy mcp_tools_select on public.mcp_tools
  for select using (public.is_org_member(organization_id));
create policy mcp_tools_insert on public.mcp_tools
  for insert with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));
create policy mcp_tools_update on public.mcp_tools
  for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));
create policy mcp_tools_delete on public.mcp_tools
  for delete using (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

-- Tool calls: the requester and privileged roles read (arguments can carry
-- credentials, so this is deliberately narrower than org-wide); lifecycle
-- writes go through the mcp-gateway as service_role.
create policy mcp_tool_calls_select on public.mcp_tool_calls
  for select using (
    public.has_org_role(organization_id, array['owner', 'admin', 'security'])
    or requested_by = auth.uid()
  );

grant execute on function public.expire_stale_approvals() to authenticated;
grant execute on function public.decide_approval(uuid, text, text) to authenticated;
