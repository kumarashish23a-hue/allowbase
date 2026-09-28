-- 026_phase_b_quick_wins.sql
-- Phase B: three small holes closed in one migration.
--
-- B1. Approval expiry. approval_requests gains expires_at (default: 24h after
--     creation). expire_stale_approvals() flips overdue pendings to 'expired'
--     and fails their linked AI requests closed to 'blocked', writing a
--     system audit row per expiry. There is no pg_cron here: the sweep runs
--     lazily — decide_approval runs it before every decision, and the
--     ai-gateway / evaluate-ai-request edge functions run it best-effort
--     before each evaluation. An expired approval can never be approved.
-- B3. Duplicate model registration. ai_models gains a unique constraint on
--     (organization_id, provider, name) after deleting accidental duplicates
--     (keeps the earliest-created row; referencing rows use on delete set
--     null, so nothing orphans). The gateway's register path retries the
--     lookup on a 23505 race so concurrent first-calls converge on one row.

-- B1. Approval expiry -----------------------------------------------------------
alter table public.approval_requests
  add column if not exists expires_at timestamptz not null default now() + interval '24 hours';

create index if not exists idx_approval_requests_expiry
  on public.approval_requests (status, expires_at)
  where status = 'pending';

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
  -- 'blocked' (the gateway only forwards allow/review decisions, so an
  -- expired approval can never be honored as an approval).
  with expired as (
    update public.approval_requests
    set status = 'expired'
    where status = 'pending' and expires_at <= now()
    returning id, organization_id, ai_request_id
  ),
  blocked as (
    update public.ai_requests r
    set status = 'blocked'
    from expired e
    where r.id = e.ai_request_id and r.status = 'pending_approval'
    returning r.id
  ),
  audited as (
    insert into public.audit_logs
      (organization_id, actor_type, action, resource_type, resource_id, result, metadata)
    select
      organization_id, 'system', 'approval_expired', 'approval_request', id, 'expired',
      jsonb_build_object('ai_request_id', ai_request_id, 'reason', 'no decision before expires_at')
    from expired
    returning 1
  )
  select count(*) into v_count from expired;
  return v_count;
end;
$$;

-- Called by our own edge functions (service_role) and by the evaluate entry
-- point under the caller's identity. No reason to expose it wider.
revoke execute on function public.expire_stale_approvals() from public, anon;
grant execute on function public.expire_stale_approvals() to authenticated;

-- decide_approval, now expiry-aware: sweep first, then refuse anything that
-- is (or has become) expired. Everything else is byte-identical to 010.
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

  update public.approval_requests
  set status = p_decision,
      decided_by = auth.uid(),
      decided_at = now(),
      note = p_note
  where id = p_approval_id;

  update public.ai_requests
  set status = v_new_status
  where id = v_approval.ai_request_id;

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
      'note', p_note,
      'self_approved', v_approval.requested_by = auth.uid()
    )
  );

  return jsonb_build_object(
    'approval_id', p_approval_id,
    'decision', p_decision,
    'ai_request_id', v_approval.ai_request_id,
    'request_status', v_new_status
  );
end;
$$;

grant execute on function public.decide_approval(uuid, text, text) to authenticated;

-- B3. Duplicate model registration ----------------------------------------------
-- Delete accidental duplicates first (keep the earliest-created row per
-- organization/provider/name). ai_requests and ai_agents reference ai_models
-- with on delete set null, so dropped duplicates leave no orphans.
delete from public.ai_models a
where exists (
  select 1
  from public.ai_models b
  where b.organization_id = a.organization_id
    and b.provider = a.provider
    and b.name = a.name
    and (b.created_at < a.created_at
         or (b.created_at = a.created_at and b.id < a.id))
);

alter table public.ai_models
  add constraint uq_ai_models_org_provider_name
  unique (organization_id, provider, name);
