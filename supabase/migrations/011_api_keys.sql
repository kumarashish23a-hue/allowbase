-- 011_api_keys.sql
-- The front door: organization-bound machine API keys + the API ingestion entry
-- point. A customer backend calls the `ingest-event` edge function with an API
-- key; the key authenticates the *organization*, and the request still runs the
-- same deterministic policy engine (evaluate_ai_request) as the app.
--
-- Security properties:
--  - The plaintext key is returned ONCE by create_api_key and never stored.
--    Only a SHA-256 hash lives in the database.
--  - Keys are minted/revoked by owner/admin only (enforced in the RPCs).
--  - ingest_api_event is SECURITY DEFINER but callable only by service_role
--    (i.e. our own edge function). It authenticates the key hash, resolves the
--    organization from the key (never from the caller), and stamps a
--    transaction-local trust marker before delegating to evaluate_ai_request.
--  - event_id gives callers idempotency: retries return the original verdict.

-- API keys --------------------------------------------------------------------
create table public.api_keys (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 100),
  key_hash text not null unique,
  key_prefix text not null,
  scopes text[] not null default array['ingest']::text[],
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create index idx_api_keys_org on public.api_keys (organization_id);
create index idx_api_keys_hash on public.api_keys (key_hash);

alter table public.api_keys enable row level security;

-- Members can read key metadata (prefix, scopes, usage). The plaintext is
-- never stored, so there is nothing secret in these rows.
create policy "api_keys_select_member"
  on public.api_keys for select
  using (public.is_org_member(organization_id));

-- Keys are minted only through create_api_key (which generates the secret
-- server-side). Direct inserts are blocked.
create policy "api_keys_no_direct_insert"
  on public.api_keys for insert
  with check (false);

-- Revocation is an update; privileged roles only (checked again in the RPC).
create policy "api_keys_update_privileged"
  on public.api_keys for update
  using (public.has_org_role(organization_id, array['owner', 'admin']))
  with check (public.has_org_role(organization_id, array['owner', 'admin']));

-- Keys are revoked, never deleted: the audit trail must keep working.
create policy "api_keys_no_delete"
  on public.api_keys for delete
  using (false);

-- Mint a key. Returns the plaintext exactly once.
create or replace function public.create_api_key(
  p_organization_id uuid,
  p_name text,
  p_scopes text[] default array['ingest']::text[],
  p_expires_at timestamptz default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key text;
  v_hash text;
  v_prefix text;
  v_id uuid;
  v_scopes text[] := coalesce(p_scopes, array['ingest']::text[]);
begin
  if not public.has_org_role(p_organization_id, array['owner', 'admin']) then
    raise exception 'creating API keys requires the owner or admin role' using errcode = '42501';
  end if;
  if p_name is null or char_length(p_name) = 0 or char_length(p_name) > 100 then
    raise exception 'key name must be 1-100 characters';
  end if;
  if not (v_scopes <@ array['ingest']::text[]) or array_length(v_scopes, 1) is null then
    raise exception 'unknown scope requested';
  end if;
  if p_expires_at is not null and p_expires_at <= now() then
    raise exception 'expiry must be in the future';
  end if;

  -- dcp_live_<64 hex chars> from 32 cryptographic random bytes.
  v_key := 'dcp_live_' || encode(gen_random_bytes(32), 'hex');
  v_hash := encode(digest(v_key, 'sha256'), 'hex');
  v_prefix := left(v_key, 12);

  insert into public.api_keys (organization_id, name, key_hash, key_prefix, scopes, expires_at, created_by)
  values (p_organization_id, p_name, v_hash, v_prefix, v_scopes, p_expires_at, auth.uid())
  returning id into v_id;

  return jsonb_build_object('id', v_id, 'key', v_key, 'prefix', v_prefix);
end;
$$;

grant execute on function public.create_api_key(uuid, text, text[], timestamptz) to authenticated;

-- Revoke a key. The row stays for audit history.
create or replace function public.revoke_api_key(p_key_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.api_keys where id = p_key_id;
  if not found then
    raise exception 'api key not found';
  end if;
  if not public.has_org_role(v_org, array['owner', 'admin']) then
    raise exception 'revoking API keys requires the owner or admin role' using errcode = '42501';
  end if;
  update public.api_keys set revoked_at = now() where id = p_key_id and revoked_at is null;
end;
$$;

grant execute on function public.revoke_api_key(uuid) to authenticated;

-- Idempotency key for API-ingested events --------------------------------------
alter table public.ai_requests add column if not exists event_id text;

create unique index if not exists uq_ai_requests_org_event
  on public.ai_requests (organization_id, event_id)
  where event_id is not null;

-- evaluate_ai_request: allow the trusted service path --------------------------
-- The body below is the 010 hardening version verbatim, with exactly one
-- change: step 1 also accepts the transaction-local app.api_key_id stamp set
-- by ingest_api_event. Generated programmatically; see scripts note in 010.
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

-- API ingestion entry point -----------------------------------------------------
-- Called only by the ingest-event edge function (service_role). It never
-- trusts an organization id from the caller: the org comes from the key.
create or replace function public.ingest_api_event(
  p_key_hash text,
  p_event_id text,
  p_ai_model_id uuid,
  p_model_name text,
  p_purpose text,
  p_data_asset_ids uuid[],
  p_agent_name text,
  p_request_type text default 'data_access'
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
    coalesce(p_request_type, 'data_access')
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

-- Only our own edge functions hold the service key.
revoke all on function public.ingest_api_event(text, text, uuid, text, text, uuid[], text, text) from public;
grant execute on function public.ingest_api_event(text, text, uuid, text, text, uuid[], text, text) to service_role;
