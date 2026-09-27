-- 012_content_detection.sql
-- Deterministic content detection in the evaluation path:
--  1. ai_requests.detection_findings — findings produced by the edge-function
--     detectors (category/severity/confidence/count only; never raw text).
--  2. New policy condition field 'content.category' with equals/not_equals/
--     in/not_in operators (any-match semantics, like data.classification).
--  3. evaluate_ai_request and ingest_api_event accept p_content_findings
--     (default '[]', so existing callers keep working) and store/return them.
--  4. A critical-severity finding (secret, private key, API key) raises risk
--     to at least 'high', even when the data assets look harmless.
--
-- The function bodies below are the 011 versions verbatim except for the
-- marked detection changes (generated programmatically with exact-match
-- replacements; see the generator note in the commit message).

-- 1. Store detection findings ------------------------------------------------
alter table public.ai_requests
  add column if not exists detection_findings jsonb not null default '[]'::jsonb;

create index if not exists idx_ai_requests_org_detection
  on public.ai_requests (organization_id, created_at);

-- 2. policy_condition_matches: content.category --------------------------------
drop function if exists public.policy_condition_matches(text, text, jsonb, uuid, uuid[], public.ai_models, text);

create or replace function public.policy_condition_matches(
  p_field text,
  p_operator text,
  p_value jsonb,
  p_org_id uuid,
  p_asset_ids uuid[],
  p_model public.ai_models,
  p_purpose text,
  p_content_findings jsonb
)
returns boolean
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_asset_val text;
  v_asset_match boolean;
  v_finding_cat text;
  v_cat_match boolean;
  v_scalar text := (p_value #>> '{}');
begin
  if p_field in ('data.classification', 'data.sensitivity_level') then
    for v_asset_val in
      select
        case
          when p_field = 'data.classification' then a.classification
          else a.sensitivity_level
        end
      from public.data_assets a
      where a.id = any (p_asset_ids)
        and a.organization_id = p_org_id
    loop
      v_asset_match := false;
      if p_operator = 'equals' then
        v_asset_match := (v_asset_val = v_scalar);
      elsif p_operator = 'not_equals' then
        v_asset_match := (v_asset_val <> v_scalar);
      elsif p_operator = 'in' then
        select exists(
          select 1 from jsonb_array_elements_text(p_value) t where t = v_asset_val
        ) into v_asset_match;
      elsif p_operator = 'not_in' then
        select not exists(
          select 1 from jsonb_array_elements_text(p_value) t where t = v_asset_val
        ) into v_asset_match;
      end if;
      -- A data condition matches when ANY requested asset matches it.
      if v_asset_match then
        return true;
      end if;
    end loop;
    return false;

  elsif p_field = 'ai.is_external' then
    if p_operator = 'equals' then
      return p_model.is_external = (v_scalar::boolean);
    elsif p_operator = 'not_equals' then
      return p_model.is_external <> (v_scalar::boolean);
    else
      return false;
    end if;

  elsif p_field = 'ai.is_approved' then
    if p_operator = 'equals' then
      return p_model.is_approved = (v_scalar::boolean);
    elsif p_operator = 'not_equals' then
      return p_model.is_approved <> (v_scalar::boolean);
    else
      return false;
    end if;

  elsif p_field = 'purpose' then
    if p_operator = 'equals' then
      return lower(coalesce(p_purpose, '')) = lower(v_scalar);
    elsif p_operator = 'not_equals' then
      return lower(coalesce(p_purpose, '')) <> lower(v_scalar);
    elsif p_operator = 'in' then
      select exists(
        select 1 from jsonb_array_elements_text(p_value) t
        where lower(t) = lower(coalesce(p_purpose, ''))
      ) into v_asset_match;
      return v_asset_match;
    else
      return false;
    end if;

  elsif p_field = 'content.category' then
    -- Matches when ANY content finding's category matches the value.
    -- Findings are produced by the edge-function detectors (never raw text).
    for v_finding_cat in
      select f ->> 'category'
      from jsonb_array_elements(coalesce(p_content_findings, '[]'::jsonb)) f
    loop
      v_cat_match := false;
      if p_operator = 'equals' then
        v_cat_match := (v_finding_cat = v_scalar);
      elsif p_operator = 'not_equals' then
        v_cat_match := (v_finding_cat <> v_scalar);
      elsif p_operator = 'in' then
        select exists(
          select 1 from jsonb_array_elements_text(p_value) t where t = v_finding_cat
        ) into v_cat_match;
      elsif p_operator = 'not_in' then
        select not exists(
          select 1 from jsonb_array_elements_text(p_value) t where t = v_finding_cat
        ) into v_cat_match;
      end if;
      -- A content condition matches when ANY finding matches it.
      if v_cat_match then
        return true;
      end if;
    end loop;
    return false;

  else
    -- Unknown fields never match (fail closed for policy authors to notice).
    return false;
  end if;
end;
$$;

grant execute on function public.policy_condition_matches(text, text, jsonb, uuid, uuid[], public.ai_models, text, jsonb) to authenticated;

-- 3. evaluate_ai_request: thread findings through --------------------------------
drop function if exists public.evaluate_ai_request(uuid, uuid, text, uuid[], uuid, uuid, text);

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
    purpose, request_type, status, risk_level, detection_findings, metadata
  )
  values (
    p_organization_id, v_actor, p_agent_id, p_ai_model_id,
    p_purpose, p_request_type, v_status, v_risk,
    coalesce(p_content_findings, '[]'::jsonb),
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
    jsonb_build_object(
      'purpose', p_purpose,
      'risk', v_risk,
      'detection_categories', coalesce(
        (select jsonb_agg(distinct f ->> 'category')
         from jsonb_array_elements(coalesce(p_content_findings, '[]'::jsonb)) f),
        '[]'::jsonb)
    )
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
    'approval_request_id', v_approval_id,
    'detections', coalesce(p_content_findings, '[]'::jsonb)
  );
end;
$$;

grant execute on function public.evaluate_ai_request(uuid, uuid, text, uuid[], uuid, uuid, text, jsonb) to authenticated;

-- 4. ingest_api_event: accept findings and delegate --------------------------------
drop function if exists public.ingest_api_event(text, text, uuid, text, text, uuid[], text, text);

create or replace function public.ingest_api_event(
  p_key_hash text,
  p_event_id text,
  p_ai_model_id uuid,
  p_model_name text,
  p_purpose text,
  p_data_asset_ids uuid[],
  p_agent_name text,
  p_request_type text default 'data_access',
  p_content_findings jsonb default '[]'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key record;
  v_org uuid;
  v_model_id uuid;
  v_agent_id uuid;
  v_replay jsonb;
  v_result jsonb;
  v_request_id uuid;
begin
  -- 1. Authenticate the key by hash. The plaintext never reaches the database.
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid api key' using errcode = '28000';
  end if;
  select * into v_key from public.api_keys where key_hash = p_key_hash;
  if not found
     or v_key.revoked_at is not null
     or (v_key.expires_at is not null and v_key.expires_at <= now())
     or not ('ingest' = any (v_key.scopes)) then
    raise exception 'invalid api key' using errcode = '28000';
  end if;
  v_org := v_key.organization_id;

  -- 2. Validate the idempotency key.
  if p_event_id is null or char_length(p_event_id) = 0 or char_length(p_event_id) > 200 then
    raise exception 'event_id is required (1-200 characters)';
  end if;

  -- 3. Serialize concurrent ingests of the same event (transaction-scoped).
  perform pg_advisory_xact_lock(hashtext(v_org::text || ':' || p_event_id)::bigint);

  -- 4. Idempotency: a retried event returns the original verdict, no re-evaluation.
  select jsonb_build_object(
      'request_id', r.id,
      'decision', case r.status
                   when 'blocked' then 'block'
                   when 'review' then 'review'
                   when 'pending_approval' then 'require_approval'
                   else 'allow' end,
      'risk', r.risk_level,
      'policies_triggered', coalesce(r.metadata -> 'policies_triggered', '[]'::jsonb),
      'detections', coalesce(r.detection_findings, '[]'::jsonb),
      'event_id', p_event_id,
      'idempotent_replay', true
    )
    into v_replay
  from public.ai_requests r
  where r.organization_id = v_org and r.event_id = p_event_id;
  if found then
    update public.api_keys set last_used_at = now() where id = v_key.id;
    return v_replay;
  end if;

  -- 5. Resolve the model: explicit id wins; otherwise find-or-provision by name.
  --    Auto-provisioned models default to external (conservative).
  if p_ai_model_id is not null then
    select id into v_model_id from public.ai_models
    where id = p_ai_model_id and organization_id = v_org;
    if not found then
      raise exception 'ai model not found in organization';
    end if;
  elsif p_model_name is not null and char_length(p_model_name) between 1 and 120 then
    select id into v_model_id from public.ai_models
    where organization_id = v_org and lower(name) = lower(p_model_name);
    if not found then
      insert into public.ai_models (organization_id, name, provider, model_identifier, is_external, metadata)
      values (v_org, p_model_name, 'external', p_model_name, true,
              jsonb_build_object('auto_provisioned', true, 'via', 'ingest_api_event'))
      returning id into v_model_id;
    end if;
  else
    raise exception 'ai_model_id or model_name is required';
  end if;

  -- 6. Resolve the agent by name. Unknown agents fail closed.
  if p_agent_name is not null and char_length(p_agent_name) > 0 then
    select id into v_agent_id from public.ai_agents
    where organization_id = v_org and lower(name) = lower(p_agent_name);
    if not found then
      raise exception 'ai agent not found in organization';
    end if;
  end if;

  -- 7. Stamp the trusted service context, then run the one real evaluator.
  perform set_config('app.api_key_id', v_key.id::text, true);
  v_result := public.evaluate_ai_request(
    v_org,
    v_model_id,
    p_purpose,
    coalesce(p_data_asset_ids, '{}'::uuid[]),
    null,
    v_agent_id,
    coalesce(p_request_type, 'data_access'),
    p_content_findings
  );
  v_request_id := (v_result ->> 'request_id')::uuid;

  -- 8. Attach the idempotency key and key reference to the stored request.
  update public.ai_requests
  set event_id = p_event_id,
      metadata = coalesce(metadata, '{}'::jsonb)
        || jsonb_build_object('api_key_id', v_key.id, 'api_key_prefix', v_key.key_prefix)
  where id = v_request_id;

  -- 9. Record the machine call itself (actor_type 'system': a key, not a person).
  insert into public.audit_logs (
    organization_id, actor_type, action, resource_type, resource_id, result, metadata
  )
  values (
    v_org, 'system', 'api_event_ingested', 'ai_request', v_request_id,
    v_result ->> 'decision',
    jsonb_build_object(
      'event_id', p_event_id,
      'api_key_id', v_key.id,
      'key_prefix', v_key.key_prefix,
      'agent_name', p_agent_name
    )
  );

  update public.api_keys set last_used_at = now() where id = v_key.id;

  return v_result || jsonb_build_object('event_id', p_event_id, 'idempotent_replay', false);
end;
$$;

grant execute on function public.ingest_api_event(text, text, uuid, text, text, uuid[], text, text, jsonb) to service_role;
