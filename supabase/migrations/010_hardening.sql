-- 010_hardening.sql
-- Phase 1 hardening:
--  1. evaluate_ai_request: every requested asset must belong to the caller's
--     organization (fail closed; previously cross-org asset ids were silently ignored).
--  2. evaluate_ai_request: enforce ai_agent_data_permissions. When a request is
--     attributed to an AI agent (p_agent_id), each requested asset must be covered
--     by a 'read' grant — either directly on the asset or on the asset's source.
--     No grant => hard block (default deny for non-human actors).
--  3. New policy action 'require_approval': triggers a pending approval instead of
--     an immediate verdict. approval_requests table + decide_approval RPC
--     (owner/admin only) + ai_requests.status 'pending_approval'.
--  4. checks.permission in the evaluation output is now real (was hardcoded true).

-- Approval requests ---------------------------------------------------------------
create table public.approval_requests (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  ai_request_id uuid not null references public.ai_requests(id) on delete cascade,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'expired')),
  requested_by uuid,
  decided_by uuid,
  decided_at timestamptz,
  note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (ai_request_id)
);

create index idx_approval_requests_org on public.approval_requests (organization_id);
create index idx_approval_requests_org_status on public.approval_requests (organization_id, status);

create trigger approval_requests_set_updated_at
  before update on public.approval_requests
  for each row execute function public.set_updated_at();

alter table public.approval_requests enable row level security;

-- Members can see approvals; only owners/admins decide (enforced again in the RPC).
create policy "approvals_select_member"
  on public.approval_requests for select
  using (public.is_org_member(organization_id));

create policy "approvals_insert_member"
  on public.approval_requests for insert
  with check (public.is_org_member(organization_id));

create policy "approvals_update_privileged"
  on public.approval_requests for update
  using (public.has_org_role(organization_id, array['owner', 'admin']))
  with check (public.has_org_role(organization_id, array['owner', 'admin']));

-- Extend the policy action and request status vocabularies --------------------------
-- (constraint names are Postgres' deterministic {table}_{column}_check names)
alter table public.policies drop constraint if exists policies_action_check;
alter table public.policies
  add constraint policies_action_check
  check (action in ('allow', 'block', 'redact', 'review', 'require_approval'));

alter table public.ai_requests drop constraint if exists ai_requests_status_check;
alter table public.ai_requests
  add constraint ai_requests_status_check
  check (status in ('pending', 'allowed', 'blocked', 'review', 'error', 'pending_approval'));

-- policy_evaluations records the action each triggered policy demanded.
alter table public.policy_evaluations drop constraint if exists policy_evaluations_decision_check;
alter table public.policy_evaluations
  add constraint policy_evaluations_decision_check
  check (decision in ('allow', 'block', 'review', 'require_approval'));

-- Hardened evaluator -----------------------------------------------------------------
create or replace function public.evaluate_ai_request(
  p_organization_id uuid,
  p_ai_model_id uuid,
  p_purpose text,
  p_data_asset_ids uuid[],
  p_user_id uuid default null,
  p_agent_id uuid default null,
  p_request_type text default 'chat'
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_model public.ai_models;
  v_agent_name text;
  v_policy record;
  v_cond jsonb;
  v_all_match boolean;
  v_triggered_ids uuid[] := '{}';
  v_triggered_names text[] := '{}';
  v_triggered_actions text[] := '{}';
  v_reasons text[] := '{}';
  v_decision text := 'allow';
  v_status text := 'allowed';
  v_risk text := 'low';  v_has_sensitive boolean := false;
  v_agent_blocked boolean := false;
  v_needs_approval boolean := false;
  v_request_id uuid;
  v_approval_id uuid;
  v_actor uuid;
  v_checks jsonb;
  v_idx integer;
begin
  -- 1. Verify organization membership. Never trust org id from the client alone.
  if not public.is_org_member(p_organization_id) then
    raise exception 'not an organization member' using errcode = '42501';
  end if;

  -- 2. Identify the model (must belong to the organization).
  select * into v_model
  from public.ai_models
  where id = p_ai_model_id and organization_id = p_organization_id;
  if not found then
    raise exception 'ai model not found in organization';
  end if;

  -- 2b. Every requested asset must belong to the organization (fail closed).
  if exists (
    select 1
    from unnest(p_data_asset_ids) as req(asset_id)
    where not exists (
      select 1 from public.data_assets a
      where a.id = req.asset_id and a.organization_id = p_organization_id
    )
  ) then
    raise exception 'one or more data assets not found in organization';
  end if;

  -- 2c. Agent attribution: verify the agent and enforce its data permissions.
  -- Default deny: an agent may only read assets it was explicitly granted,
  -- either directly or via the asset's data source.
  if p_agent_id is not null then
    select name into v_agent_name
    from public.ai_agents
    where id = p_agent_id and organization_id = p_organization_id;
    if not found then
      raise exception 'ai agent not found in organization';
    end if;

    select exists (
      select 1
      from unnest(p_data_asset_ids) as req(asset_id)
      join public.data_assets a on a.id = req.asset_id
      where not exists (
        select 1 from public.ai_agent_data_permissions p
        where p.agent_id = p_agent_id
          and p.permission_type = 'read'
          and (
            p.data_asset_id = req.asset_id
            or p.data_source_id = a.data_source_id
          )
      )
    ) into v_agent_blocked;

    if v_agent_blocked then
      v_reasons := v_reasons ||
        ('AI agent "' || v_agent_name || '" has no read permission for one or more requested data assets.');
    end if;
  end if;

  -- 3/4. Inspect requested assets and their classifications.
  select exists(
    select 1
    from public.data_assets a
    where a.id = any (p_data_asset_ids)
      and a.organization_id = p_organization_id
      and (
        a.sensitivity_level in ('medium', 'high', 'critical')
        or a.classification in ('confidential', 'restricted')
      )
  ) into v_has_sensitive;

  -- 5/6. Load active policies (priority order) and evaluate conditions.
  for v_policy in
    select *
    from public.policies
    where organization_id = p_organization_id
      and status = 'active'
    order by priority asc, created_at asc
  loop
    v_all_match := true;
    for v_cond in
      select * from jsonb_array_elements(coalesce(v_policy.rule -> 'conditions', '[]'::jsonb))
    loop
      if not public.policy_condition_matches(
        v_cond ->> 'field',
        coalesce(v_cond ->> 'operator', 'equals'),
        v_cond -> 'value',
        p_organization_id,
        p_data_asset_ids,
        v_model,
        p_purpose
      ) then
        v_all_match := false;
        exit;
      end if;
    end loop;

    if v_all_match then
      v_triggered_ids := v_triggered_ids || v_policy.id;
      v_triggered_names := v_triggered_names || v_policy.name;
      v_triggered_actions := v_triggered_actions || v_policy.action;
      v_reasons := v_reasons || coalesce(v_policy.description, v_policy.name);
    end if;
  end loop;

  -- 7. Determine the decision: most restrictive triggered action wins.
  -- An agent permission failure is a hard block and outranks policy actions.
  if v_agent_blocked then
    v_decision := 'block';
    v_triggered_names := array_append(v_triggered_names, 'Agent data permission check');
    v_triggered_actions := array_append(v_triggered_actions, 'block');
  elsif 'block' = any (v_triggered_actions) then
    v_decision := 'block';
  elsif 'require_approval' = any (v_triggered_actions) then
    v_decision := 'review';
    v_needs_approval := true;
  elsif 'review' = any (v_triggered_actions) or 'redact' = any (v_triggered_actions) then
    v_decision := 'review';
  else
    v_decision := 'allow';
  end if;

  -- 8. Calculate risk.
  select
    case
      when exists(
        select 1 from public.data_assets a
        where a.id = any (p_data_asset_ids)
          and a.organization_id = p_organization_id
          and (a.sensitivity_level in ('high', 'critical') or a.classification = 'restricted')
      ) then 'high'
      when v_has_sensitive then 'medium'
      else 'low'
    end
  into v_risk;
  if v_decision = 'block' and v_risk = 'low' then
    v_risk := 'high';
  end if;

  -- Map the policy decision to the ai_requests status vocabulary.
  v_status := case v_decision
    when 'block' then 'blocked'
    when 'review' then (case when v_needs_approval then 'pending_approval' else 'review' end)
    else 'allowed'
  end;

  v_actor := coalesce(p_user_id, auth.uid());

  v_checks := jsonb_build_object(
    'identity', v_actor is not null or p_agent_id is not null,
    'permission', not v_agent_blocked,
    'data_classification', not v_has_sensitive,
    'ai_destination', not (v_model.is_external and v_has_sensitive),
    'purpose', coalesce(p_purpose, '') <> ''
  );

  -- 9. Store the request.
  insert into public.ai_requests (
    organization_id, user_id, agent_id, ai_model_id,
    purpose, request_type, status, risk_level, metadata
  )
  values (
    p_organization_id, v_actor, p_agent_id, p_ai_model_id,
    p_purpose, p_request_type, v_status, v_risk,
    jsonb_build_object(
      'evaluated_at', now(),
      'policies_triggered', to_jsonb(v_triggered_names)
    )
  )
  returning id into v_request_id;

  -- 9b. Open an approval request when a policy requires human approval.
  if v_needs_approval then
    insert into public.approval_requests (organization_id, ai_request_id, requested_by)
    values (p_organization_id, v_request_id, v_actor)
    returning id into v_approval_id;
  end if;

  -- 10. Link data assets.
  insert into public.ai_request_data (ai_request_id, data_asset_id, access_type)
  select v_request_id, asset_id, 'read'
  from unnest(p_data_asset_ids) as asset_id
  on conflict do nothing;

  -- 11. Store one evaluation row per triggered policy.
  for v_idx in 1 .. coalesce(array_length(v_triggered_ids, 1), 0)
  loop
    insert into public.policy_evaluations (ai_request_id, policy_id, decision, reason, checks)
    values (
      v_request_id,
      v_triggered_ids[v_idx],
      case v_triggered_actions[v_idx] when 'redact' then 'review' else v_triggered_actions[v_idx] end,
      v_reasons[v_idx],
      v_checks
    );
  end loop;

  -- 12. Append to the audit log (insert-only by RLS).
  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action,
    resource_type, resource_id, result, metadata
  )
  values (
    p_organization_id,
    v_actor,
    case when p_agent_id is not null then 'ai_agent' else 'user' end,
    'ai_request_' || v_decision,
    'ai_request',
    v_request_id,
    v_decision,
    jsonb_build_object('purpose', p_purpose, 'risk', v_risk)
  );

  -- 13. Raise a risk event for blocks, reviews, or high risk.
  if v_decision in ('block', 'review') or v_risk in ('high', 'critical') then
    insert into public.risk_events (
      organization_id, ai_request_id, ai_agent_id,
      title, description, severity, status, recommended_action, metadata
    )
    values (
      p_organization_id,
      v_request_id,
      p_agent_id,
      'AI request ' || v_decision || ' (' || v_risk || ' risk)',
      array_to_string(v_reasons, ' '),
      case when v_risk = 'critical' then 'critical' when v_risk = 'high' then 'high' else 'medium' end,
      'open',
      case v_decision
        when 'block' then 'Review the triggered policies before retrying.'
        when 'review' then 'Manually review this request in the audit log.'
        else 'Monitor for repeated high-risk access.'
      end,
      jsonb_build_object('policies_triggered', to_jsonb(v_triggered_names))
    );
  end if;

  -- 14. Structured response.
  return jsonb_build_object(
    'request_id', v_request_id,
    'decision', v_decision,
    'risk', v_risk,
    'reasons', to_jsonb(v_reasons),
    'policies_triggered', to_jsonb(v_triggered_names),
    'checks', v_checks,
    'approval_required', v_needs_approval,
    'approval_request_id', v_approval_id
  );
end;
$$;

grant execute on function public.evaluate_ai_request(uuid, uuid, text, uuid[], uuid, uuid, text) to authenticated;

-- Decide an approval request ----------------------------------------------------------
-- Only owners/admins may decide. The linked AI request moves to allowed/blocked,
-- and the decision itself is written to the append-only audit log.
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

  select * into v_approval
  from public.approval_requests
  where id = p_approval_id;
  if not found then
    raise exception 'approval request not found';
  end if;
  if v_approval.status <> 'pending' then
    raise exception 'approval request is no longer pending';
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
