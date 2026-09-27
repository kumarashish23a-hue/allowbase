-- 015_enforcement_mode.sql
--
-- Monitor vs Enforce per workspace.
--   monitor: detect and log only. Policies are still evaluated and the
--            would-be decision is recorded (request metadata, audit log,
--            risk events, API response) — but the request is allowed and no
--            approval request is opened.
--   enforce: policy decisions are applied (block / require approval).
--
-- New organizations default to MONITOR. Existing organizations keep their
-- current behavior (ENFORCE) so this migration never silently weakens a
-- live workspace.
--
-- Run once in the Supabase SQL editor, then redeploy the edge functions
-- (no function code changes are needed — the mode is enforced inside the
-- evaluate_ai_request Postgres function).

-- 1. Column on organizations.
alter table public.organizations
  add column if not exists enforcement_mode text not null default 'monitor'
  check (enforcement_mode in ('monitor', 'enforce'));

comment on column public.organizations.enforcement_mode is
  'monitor: detect and log only, would-be decision recorded. enforce: policy decisions applied.';

-- 2. Preserve current behavior for existing workspaces.
update public.organizations set enforcement_mode = 'enforce';

-- 3. evaluate_ai_request honors the workspace enforcement mode.
create or replace function public.evaluate_ai_request(
  p_organization_id uuid,
  p_ai_model_id uuid,
  p_purpose text,
  p_data_asset_ids uuid[],
  p_user_id uuid default null,
  p_agent_id uuid default null,
  p_request_type text default 'chat',
  p_content_findings jsonb default '[]'::jsonb
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
  v_has_critical_finding boolean := false;
  v_idx integer;
  v_enforcement_mode text;
  v_would_decision text := null;
  v_enforced boolean := true;
begin
  -- 1. Verify organization membership. Never trust org id from the client alone.
  --    Service path: ingest_api_event authenticates an organization-bound API key
  --    and stamps the trusted key id in the transaction-local app.api_key_id
  --    setting before delegating here. That stamp is only ever set by our own
  --    edge functions (the service key never leaves Supabase), so it replaces
  --    the membership check for machine callers.
  if current_setting('app.api_key_id', true) is null
     and not public.is_org_member(p_organization_id) then
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

  -- 4b. Content detection findings (scanned by the edge function; the raw
  -- content itself is never sent to the database).
  select exists (
    select 1
    from jsonb_array_elements(coalesce(p_content_findings, '[]'::jsonb)) f
    where f ->> 'severity' = 'critical'
  ) into v_has_critical_finding;

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
        p_purpose,
        p_content_findings
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

  -- 7b. Enforcement mode: monitor detects and logs but never blocks.
  -- The would-be decision is recorded everywhere (request metadata, audit,
  -- risk events, response) so nothing is silently dropped.
  select o.enforcement_mode into v_enforcement_mode
  from public.organizations o
  where o.id = p_organization_id;

  if v_enforcement_mode = 'monitor' and v_decision in ('block', 'review') then
    v_would_decision := v_decision;
    v_decision := 'allow';
    v_needs_approval := false;
    v_enforced := false;
  end if;

  -- 8. Calculate risk.
  select
    case
      when v_has_critical_finding then 'high'
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
  if (v_decision = 'block' or v_would_decision = 'block') and v_risk = 'low' then
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
    purpose, request_type, status, risk_level, detection_findings, metadata
  )
  values (
    p_organization_id, v_actor, p_agent_id, p_ai_model_id,
    p_purpose, p_request_type, v_status, v_risk,
    coalesce(p_content_findings, '[]'::jsonb),
    jsonb_build_object(
      'evaluated_at', now(),
      'policies_triggered', to_jsonb(v_triggered_names),
      'enforcement_mode', v_enforcement_mode,
      'enforced', v_enforced,
      'would_decision', v_would_decision
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
    jsonb_build_object(
      'purpose', p_purpose,
      'risk', v_risk,
      'detection_categories', coalesce(
        (select jsonb_agg(distinct f ->> 'category')
         from jsonb_array_elements(coalesce(p_content_findings, '[]'::jsonb)) f),
        '[]'::jsonb),
      'enforcement_mode', v_enforcement_mode,
      'enforced', v_enforced,
      'would_decision', v_would_decision
    )
  );

  -- 13. Raise a risk event for blocks, reviews, or high risk.
  -- In monitor mode a would-block / would-review still raises an event:
  -- that visibility is the entire point of monitoring.
  if v_would_decision is not null or v_decision in ('block', 'review') or v_risk in ('high', 'critical') then
    insert into public.risk_events (
      organization_id, ai_request_id, ai_agent_id,
      title, description, severity, status, recommended_action, metadata
    )
    values (
      p_organization_id,
      v_request_id,
      p_agent_id,
      'AI request ' || coalesce(v_would_decision, v_decision) || ' (' || v_risk || ' risk)' ||
        case when v_would_decision is not null then ' — monitor mode, allowed' else '' end,
      array_to_string(v_reasons, ' '),
      case when v_risk = 'critical' then 'critical' when v_risk = 'high' then 'high' else 'medium' end,
      'open',
      case
        when v_would_decision is not null then 'No action was taken (monitor mode). Switch the workspace to Enforce to block these requests.'
        when v_decision = 'block' then 'Review the triggered policies before retrying.'
        when v_decision = 'review' then 'Manually review this request in the audit log.'
        else 'Monitor for repeated high-risk access.'
      end,
      jsonb_build_object(
        'policies_triggered', to_jsonb(v_triggered_names),
        'enforcement_mode', v_enforcement_mode,
        'enforced', v_enforced,
        'would_decision', v_would_decision
      )
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
    'approval_request_id', v_approval_id,
    'detections', coalesce(p_content_findings, '[]'::jsonb),
    'enforced', v_enforced,
    'would_decision', v_would_decision,
    'enforcement_mode', v_enforcement_mode
  );
end;
$$;

grant execute on function public.evaluate_ai_request(uuid, uuid, text, uuid[], uuid, uuid, text, jsonb) to authenticated;
