-- 008_functions.sql
-- create_organization, evaluate_ai_request, dashboard RPCs.

-- Create an organization and make the caller its owner --------------------------
create or replace function public.create_organization(p_name text, p_slug text default null)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
  v_slug text;
begin
  if auth.uid() is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;

  v_slug := coalesce(
    nullif(p_slug, ''),
    lower(regexp_replace(p_name, '[^a-zA-Z0-9]+', '-', 'g'))
      || '-' || substr(gen_random_uuid()::text, 1, 8)
  );

  insert into public.organizations (name, slug)
  values (p_name, v_slug)
  returning id into v_id;

  insert into public.organization_members (organization_id, user_id, role, status)
  values (v_id, auth.uid(), 'owner', 'active');

  return v_id;
end;
$$;

grant execute on function public.create_organization(text, text) to authenticated;

-- Single policy-condition matcher -------------------------------------------------
-- Supported fields: data.classification, data.sensitivity_level,
-- ai.is_external, ai.is_approved, purpose.
-- Operators: equals, not_equals, in, not_in.
create or replace function public.policy_condition_matches(
  p_field text,
  p_operator text,
  p_value jsonb,
  p_org_id uuid,
  p_asset_ids uuid[],
  p_model public.ai_models,
  p_purpose text
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

  else
    -- Unknown fields never match (fail closed for policy authors to notice).
    return false;
  end if;
end;
$$;

grant execute on function public.policy_condition_matches(text, text, jsonb, uuid, uuid[], public.ai_models, text) to authenticated;

-- Main policy evaluation -------------------------------------------------------------
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
  v_request_id uuid;
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
  if 'block' = any (v_triggered_actions) then
    v_decision := 'block';
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
    when 'review' then 'review'
    else 'allowed'
  end;

  v_actor := coalesce(p_user_id, auth.uid());

  v_checks := jsonb_build_object(
    'identity', v_actor is not null or p_agent_id is not null,
    'permission', true,
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
    'checks', v_checks
  );
end;
$$;

grant execute on function public.evaluate_ai_request(uuid, uuid, text, uuid[], uuid, uuid, text) to authenticated;

-- Dashboard RPCs --------------------------------------------------------------------------
-- Aggregates run in SQL so the browser never fetches every record.

create or replace function public.get_dashboard_metrics(p_organization_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_result jsonb;
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'not an organization member' using errcode = '42501';
  end if;

  select jsonb_build_object(
    'total_requests', count(*),
    'allowed', count(*) filter (where status = 'allowed'),
    'blocked', count(*) filter (where status = 'blocked'),
    'in_review', count(*) filter (where status = 'review')
  )
  into v_result
  from public.ai_requests
  where organization_id = p_organization_id;

  v_result := v_result
    || jsonb_build_object(
      'sensitive_events',
      (select count(*) from public.sensitive_data_findings
       where organization_id = p_organization_id and status = 'open'),
      'active_agents',
      (select count(*) from public.ai_agents
       where organization_id = p_organization_id and status = 'active'),
      'high_risk',
      (select count(*) from public.risk_events
       where organization_id = p_organization_id
         and status = 'open'
         and severity in ('high', 'critical'))
    );

  return v_result;
end;
$$;

grant execute on function public.get_dashboard_metrics(uuid) to authenticated;

create or replace function public.get_requests_over_time(p_organization_id uuid, p_days integer default 7)
returns table (bucket text, requests bigint, blocked bigint)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'not an organization member' using errcode = '42501';
  end if;

  return query
  with days as (
    select generate_series(
      date_trunc('day', now()) - (p_days - 1) * interval '1 day',
      date_trunc('day', now()),
      interval '1 day'
    ) as day
  )
  select
    to_char(d.day, 'Mon DD'),
    count(r.id),
    count(r.id) filter (where r.status = 'blocked')
  from days d
  left join public.ai_requests r
    on r.organization_id = p_organization_id
    and date_trunc('day', r.created_at) = d.day
  group by d.day
  order by d.day;
end;
$$;

grant execute on function public.get_requests_over_time(uuid, integer) to authenticated;

create or replace function public.get_risk_distribution(p_organization_id uuid)
returns table (name text, value bigint)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'not an organization member' using errcode = '42501';
  end if;

  return query
  select
    case
      when r.risk_level in ('high', 'critical') then 'High'
      when r.risk_level = 'medium' then 'Medium'
      else 'Low'
    end,
    count(*)
  from public.ai_requests r
  where r.organization_id = p_organization_id
  group by 1
  order by 1;
end;
$$;

grant execute on function public.get_risk_distribution(uuid) to authenticated;

create or replace function public.get_model_usage(p_organization_id uuid)
returns table (model text, requests bigint)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'not an organization member' using errcode = '42501';
  end if;

  return query
  select m.name, count(r.id)
  from public.ai_models m
  left join public.ai_requests r
    on r.ai_model_id = m.id
  where m.organization_id = p_organization_id
  group by m.name
  order by count(r.id) desc;
end;
$$;

grant execute on function public.get_model_usage(uuid) to authenticated;

create or replace function public.get_source_usage(p_organization_id uuid)
returns table (source text, requests bigint)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'not an organization member' using errcode = '42501';
  end if;

  return query
  select s.name, count(distinct rd.ai_request_id)
  from public.data_sources s
  left join public.data_assets a on a.data_source_id = s.id
  left join public.ai_request_data rd on rd.data_asset_id = a.id
  where s.organization_id = p_organization_id
  group by s.name
  order by count(distinct rd.ai_request_id) desc;
end;
$$;

grant execute on function public.get_source_usage(uuid) to authenticated;
