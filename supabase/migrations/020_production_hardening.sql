-- 020_production_hardening.sql
--
-- Production hardening for the control plane:
--   1. Rate limiting        — fixed-window counters, service-role only.
--   2. Policy versioning    — immutable snapshots on every change + rollback.
--   3. API key security     — CIDR allow-lists, per-key rate limits, rotation,
--                             revocation reasons, emergency revoke-all, usage.
--   4. Approval workflow    — expiry, escalation, delegation, comments, timeline.
--   5. Monitoring           — per-request metrics (latency, tokens, cost, outcome)
--                             and an alerting summary RPC.
--
-- Idempotent where practical: safe to re-run on a project that partially applied it.

-- =====================================================================================
-- 1. Rate limiting
-- =====================================================================================
create table if not exists public.rate_limit_counters (
  bucket text not null,
  window_start timestamptz not null,
  hits integer not null default 0,
  primary key (bucket, window_start)
);

-- RLS on, no policies: only service_role (and security definer functions) touch it.
alter table public.rate_limit_counters enable row level security;

create or replace function public.check_rate_limit(
  p_bucket text,
  p_limit integer,
  p_window_seconds integer default 60
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_window timestamptz;
  v_hits integer;
begin
  if p_bucket is null or char_length(p_bucket) = 0 or char_length(p_bucket) > 200 then
    raise exception 'rate limit bucket must be 1-200 characters';
  end if;
  if p_limit is null or p_limit < 1 or p_limit > 100000 then
    raise exception 'rate limit must be between 1 and 100000';
  end if;
  if p_window_seconds is null or p_window_seconds < 1 or p_window_seconds > 86400 then
    raise exception 'rate limit window must be between 1 and 86400 seconds';
  end if;

  v_window := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);

  insert into public.rate_limit_counters as c (bucket, window_start, hits)
  values (p_bucket, v_window, 1)
  on conflict (bucket, window_start) do update set hits = c.hits + 1
  returning hits into v_hits;

  -- Opportunistic cleanup keeps the table small without a cron job.
  if random() < 0.01 then
    delete from public.rate_limit_counters where window_start < now() - interval '1 day';
  end if;

  return jsonb_build_object(
    'allowed', v_hits <= p_limit,
    'limit', p_limit,
    'remaining', greatest(p_limit - v_hits, 0),
    'reset_at', v_window + make_interval(secs => p_window_seconds)
  );
end;
$$;

revoke all on function public.check_rate_limit(text, integer, integer) from public;
grant execute on function public.check_rate_limit(text, integer, integer) to service_role;

-- =====================================================================================
-- 2. Policy versioning
-- =====================================================================================
alter table public.policies add column if not exists version integer not null default 1;

create table if not exists public.policy_versions (
  id uuid primary key default gen_random_uuid(),
  -- No FK: history must survive the policy being deleted.
  policy_id uuid not null,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  version integer not null,
  change_type text not null
    check (change_type in ('created', 'updated', 'status_changed', 'deleted', 'rolled_back')),
  name text not null,
  description text,
  status text not null,
  priority integer not null,
  rule jsonb not null,
  action text not null,
  rolled_back_from integer,
  changed_by uuid,
  created_at timestamptz not null default now(),
  unique (policy_id, version)
);

create index if not exists idx_policy_versions_policy on public.policy_versions (policy_id, version desc);
create index if not exists idx_policy_versions_org on public.policy_versions (organization_id, created_at desc);

alter table public.policy_versions enable row level security;

drop policy if exists "policy_versions_select_member" on public.policy_versions;
create policy "policy_versions_select_member"
  on public.policy_versions for select
  using (public.is_org_member(organization_id));
-- No insert/update/delete policies: versions are written only by the trigger and
-- are immutable for every client role.

create or replace function public.policy_bump_version()
returns trigger
language plpgsql
as $$
begin
  if (new.name, new.description, new.status, new.priority, new.rule, new.action)
     is distinct from
     (old.name, old.description, old.status, old.priority, old.rule, old.action) then
    new.version := old.version + 1;
  else
    new.version := old.version;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_policies_bump_version on public.policies;
create trigger trg_policies_bump_version
  before update on public.policies
  for each row execute function public.policy_bump_version();

create or replace function public.policy_record_version()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_rollback_from integer := nullif(current_setting('allowbase.rollback_from', true), '')::integer;
  v_change text;
begin
  if tg_op = 'DELETE' then
    insert into public.policy_versions (
      policy_id, organization_id, version, change_type, name, description,
      status, priority, rule, action, changed_by
    ) values (
      old.id, old.organization_id, old.version + 1, 'deleted', old.name, old.description,
      old.status, old.priority, old.rule, old.action, auth.uid()
    )
    on conflict (policy_id, version) do nothing;
    return old;
  end if;

  if tg_op = 'UPDATE' and new.version = old.version then
    return new;
  end if;

  if v_rollback_from is not null then
    v_change := 'rolled_back';
  elsif tg_op = 'INSERT' then
    v_change := 'created';
  elsif (new.name, new.description, new.priority, new.rule, new.action)
        is not distinct from (old.name, old.description, old.priority, old.rule, old.action) then
    v_change := 'status_changed';
  else
    v_change := 'updated';
  end if;

  insert into public.policy_versions (
    policy_id, organization_id, version, change_type, name, description,
    status, priority, rule, action, rolled_back_from, changed_by
  ) values (
    new.id, new.organization_id, new.version, v_change, new.name, new.description,
    new.status, new.priority, new.rule, new.action, v_rollback_from, auth.uid()
  )
  on conflict (policy_id, version) do nothing;
  return new;
end;
$$;

drop trigger if exists trg_policies_record_version on public.policies;
create trigger trg_policies_record_version
  after insert or update or delete on public.policies
  for each row execute function public.policy_record_version();

-- Backfill: every existing policy gets its current state as version 1.
insert into public.policy_versions (
  policy_id, organization_id, version, change_type, name, description,
  status, priority, rule, action, changed_by, created_at
)
select p.id, p.organization_id, p.version, 'created', p.name, p.description,
       p.status, p.priority, p.rule, p.action, p.created_by, p.updated_at
from public.policies p
on conflict (policy_id, version) do nothing;

-- Restore a policy to an earlier version. Works for deleted policies too
-- (the policy is re-created with its original id). Creates a NEW version —
-- history is never rewritten.
create or replace function public.rollback_policy(p_policy_id uuid, p_version integer)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_target public.policy_versions;
  v_exists boolean;
  v_next integer;
  v_new_version integer;
begin
  select * into v_target
  from public.policy_versions
  where policy_id = p_policy_id and version = p_version;
  if not found then
    raise exception 'policy version not found';
  end if;
  if not public.has_org_role(v_target.organization_id, array['owner', 'admin', 'security']) then
    raise exception 'rolling back policies requires the owner, admin, or security role' using errcode = '42501';
  end if;
  if v_target.change_type = 'deleted' then
    raise exception 'cannot roll back to a deletion; choose an earlier version';
  end if;

  perform set_config('allowbase.rollback_from', p_version::text, true);

  select exists (select 1 from public.policies where id = p_policy_id) into v_exists;
  if v_exists then
    update public.policies
    set name = v_target.name,
        description = v_target.description,
        status = v_target.status,
        priority = v_target.priority,
        rule = v_target.rule,
        action = v_target.action
    where id = p_policy_id
    returning version into v_new_version;
  else
    select coalesce(max(version), 0) + 1 into v_next
    from public.policy_versions where policy_id = p_policy_id;
    insert into public.policies (
      id, organization_id, name, description, status, priority, rule, action, created_by, version
    ) values (
      p_policy_id, v_target.organization_id, v_target.name, v_target.description,
      v_target.status, v_target.priority, v_target.rule, v_target.action, auth.uid(), v_next
    )
    returning version into v_new_version;
  end if;

  perform set_config('allowbase.rollback_from', '', true);

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata
  ) values (
    v_target.organization_id, auth.uid(), 'user', 'policy_rolled_back', 'policy', p_policy_id, 'success',
    jsonb_build_object('restored_version', p_version, 'new_version', v_new_version, 'recreated', not v_exists)
  );

  return jsonb_build_object(
    'policy_id', p_policy_id,
    'restored_version', p_version,
    'new_version', v_new_version,
    'recreated', not v_exists
  );
end;
$$;

revoke all on function public.rollback_policy(uuid, integer) from public;
grant execute on function public.rollback_policy(uuid, integer) to authenticated;

-- =====================================================================================
-- 3. API key security
-- =====================================================================================
alter table public.api_keys add column if not exists allowed_cidrs cidr[] not null default '{}';
alter table public.api_keys add column if not exists rate_limit_per_minute integer not null default 120;
alter table public.api_keys add column if not exists rotated_from uuid references public.api_keys(id) on delete set null;
alter table public.api_keys add column if not exists revoked_reason text;
alter table public.api_keys add column if not exists last_used_ip inet;
alter table public.api_keys add column if not exists use_count bigint not null default 0;

alter table public.api_keys drop constraint if exists api_keys_rate_limit_range;
alter table public.api_keys
  add constraint api_keys_rate_limit_range check (rate_limit_per_minute between 1 and 10000);
alter table public.api_keys drop constraint if exists api_keys_cidr_count;
alter table public.api_keys
  add constraint api_keys_cidr_count check (coalesce(array_length(allowed_cidrs, 1), 0) <= 20);

-- Existing keys keep their current behaviour: ingest + raw-content scanning.
update public.api_keys
set scopes = array['ingest', 'ingest:content']::text[]
where scopes = array['ingest']::text[];

create or replace function public.api_key_valid_scopes(p_scopes text[])
returns boolean
language sql
immutable
as $$
  select p_scopes is not null
     and array_length(p_scopes, 1) is not null
     and p_scopes <@ array['ingest', 'ingest:content']::text[]
     and 'ingest' = any(p_scopes);
$$;

-- Internal mint helper shared by create and rotate. Never granted to clients.
create or replace function public.mint_api_key_internal(
  p_organization_id uuid,
  p_name text,
  p_scopes text[],
  p_expires_at timestamptz,
  p_allowed_cidrs cidr[],
  p_rate_limit_per_minute integer,
  p_rotated_from uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_key text;
  v_hash text;
  v_prefix text;
  v_id uuid;
begin
  v_key := 'dcp_live_' || encode(gen_random_bytes(32), 'hex');
  v_hash := encode(digest(v_key, 'sha256'), 'hex');
  v_prefix := left(v_key, 12);

  insert into public.api_keys (
    organization_id, name, key_hash, key_prefix, scopes, expires_at, created_by,
    allowed_cidrs, rate_limit_per_minute, rotated_from
  ) values (
    p_organization_id, p_name, v_hash, v_prefix, p_scopes, p_expires_at, auth.uid(),
    coalesce(p_allowed_cidrs, '{}'), p_rate_limit_per_minute, p_rotated_from
  )
  returning id into v_id;

  return jsonb_build_object('id', v_id, 'key', v_key, 'prefix', v_prefix);
end;
$$;

revoke all on function public.mint_api_key_internal(uuid, text, text[], timestamptz, cidr[], integer, uuid) from public;

drop function if exists public.create_api_key(uuid, text, text[], timestamptz);

create or replace function public.create_api_key(
  p_organization_id uuid,
  p_name text,
  p_scopes text[] default array['ingest', 'ingest:content']::text[],
  p_expires_at timestamptz default null,
  p_allowed_cidrs cidr[] default '{}',
  p_rate_limit_per_minute integer default 120
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_result jsonb;
begin
  if not public.has_org_role(p_organization_id, array['owner', 'admin']) then
    raise exception 'creating API keys requires the owner or admin role' using errcode = '42501';
  end if;
  if p_name is null or char_length(trim(p_name)) = 0 or char_length(p_name) > 100 then
    raise exception 'key name must be 1-100 characters';
  end if;
  if not public.api_key_valid_scopes(p_scopes) then
    raise exception 'scopes must include ingest and may only contain ingest, ingest:content';
  end if;
  if p_expires_at is not null and p_expires_at <= now() then
    raise exception 'expiry must be in the future';
  end if;
  if coalesce(array_length(p_allowed_cidrs, 1), 0) > 20 then
    raise exception 'at most 20 allowed IP ranges per key';
  end if;
  if p_rate_limit_per_minute is null or p_rate_limit_per_minute < 1 or p_rate_limit_per_minute > 10000 then
    raise exception 'rate limit must be between 1 and 10000 requests per minute';
  end if;

  v_result := public.mint_api_key_internal(
    p_organization_id, trim(p_name), p_scopes, p_expires_at,
    p_allowed_cidrs, p_rate_limit_per_minute, null
  );

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata
  ) values (
    p_organization_id, auth.uid(), 'user', 'api_key_created', 'api_key', (v_result ->> 'id')::uuid, 'success',
    jsonb_build_object(
      'prefix', v_result ->> 'prefix',
      'scopes', to_jsonb(p_scopes),
      'ip_restricted', coalesce(array_length(p_allowed_cidrs, 1), 0) > 0,
      'rate_limit_per_minute', p_rate_limit_per_minute
    )
  );

  return v_result;
end;
$$;

revoke all on function public.create_api_key(uuid, text, text[], timestamptz, cidr[], integer) from public;
grant execute on function public.create_api_key(uuid, text, text[], timestamptz, cidr[], integer) to authenticated;

drop function if exists public.revoke_api_key(uuid);

create or replace function public.revoke_api_key(p_key_id uuid, p_reason text default null)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key public.api_keys;
begin
  select * into v_key from public.api_keys where id = p_key_id;
  if not found then
    raise exception 'API key not found';
  end if;
  if not public.has_org_role(v_key.organization_id, array['owner', 'admin']) then
    raise exception 'revoking API keys requires the owner or admin role' using errcode = '42501';
  end if;
  if p_reason is not null and char_length(p_reason) > 500 then
    raise exception 'reason must be at most 500 characters';
  end if;

  update public.api_keys
  set revoked_at = now(), revoked_reason = nullif(trim(p_reason), '')
  where id = p_key_id and revoked_at is null;

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata
  ) values (
    v_key.organization_id, auth.uid(), 'user', 'api_key_revoked', 'api_key', p_key_id, 'success',
    jsonb_build_object('prefix', v_key.key_prefix, 'reason', nullif(trim(p_reason), ''))
  );

  return jsonb_build_object('id', p_key_id, 'revoked', true);
end;
$$;

revoke all on function public.revoke_api_key(uuid, text) from public;
grant execute on function public.revoke_api_key(uuid, text) to authenticated;

-- Emergency: revoke every live key in the organization at once.
create or replace function public.revoke_all_api_keys(p_organization_id uuid, p_reason text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  if not public.has_org_role(p_organization_id, array['owner', 'admin']) then
    raise exception 'emergency revocation requires the owner or admin role' using errcode = '42501';
  end if;
  if p_reason is null or char_length(trim(p_reason)) = 0 or char_length(p_reason) > 500 then
    raise exception 'a reason (1-500 characters) is required for emergency revocation';
  end if;

  with revoked as (
    update public.api_keys
    set revoked_at = now(), revoked_reason = 'emergency: ' || trim(p_reason)
    where organization_id = p_organization_id and revoked_at is null
    returning id
  )
  select count(*) into v_count from revoked;

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action, resource_type, result, metadata
  ) values (
    p_organization_id, auth.uid(), 'user', 'api_keys_emergency_revoked', 'api_key', 'success',
    jsonb_build_object('revoked_count', v_count, 'reason', trim(p_reason))
  );

  return jsonb_build_object('revoked_count', v_count);
end;
$$;

revoke all on function public.revoke_all_api_keys(uuid, text) from public;
grant execute on function public.revoke_all_api_keys(uuid, text) to authenticated;

-- Rotate: mint a replacement with the same settings; the old key keeps working
-- for the grace period so deployments can roll over without downtime.
create or replace function public.rotate_api_key(p_key_id uuid, p_grace_hours integer default 24)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key public.api_keys;
  v_result jsonb;
  v_new_expiry timestamptz;
begin
  select * into v_key from public.api_keys where id = p_key_id;
  if not found then
    raise exception 'API key not found';
  end if;
  if not public.has_org_role(v_key.organization_id, array['owner', 'admin']) then
    raise exception 'rotating API keys requires the owner or admin role' using errcode = '42501';
  end if;
  if v_key.revoked_at is not null or (v_key.expires_at is not null and v_key.expires_at <= now()) then
    raise exception 'only live keys can be rotated';
  end if;
  if p_grace_hours is null or p_grace_hours < 0 or p_grace_hours > 168 then
    raise exception 'grace period must be between 0 and 168 hours';
  end if;

  v_new_expiry := case
    when v_key.expires_at is not null and v_key.expires_at > now() then v_key.expires_at
    else null
  end;

  v_result := public.mint_api_key_internal(
    v_key.organization_id, v_key.name, v_key.scopes, v_new_expiry,
    v_key.allowed_cidrs, v_key.rate_limit_per_minute, v_key.id
  );

  if p_grace_hours = 0 then
    update public.api_keys
    set revoked_at = now(), revoked_reason = 'rotated'
    where id = v_key.id;
  else
    update public.api_keys
    set expires_at = least(coalesce(expires_at, 'infinity'::timestamptz), now() + make_interval(hours => p_grace_hours))
    where id = v_key.id;
  end if;

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata
  ) values (
    v_key.organization_id, auth.uid(), 'user', 'api_key_rotated', 'api_key', v_key.id, 'success',
    jsonb_build_object(
      'old_prefix', v_key.key_prefix,
      'new_key_id', v_result ->> 'id',
      'new_prefix', v_result ->> 'prefix',
      'grace_hours', p_grace_hours
    )
  );

  return v_result || jsonb_build_object('grace_hours', p_grace_hours, 'rotated_from', v_key.id);
end;
$$;

revoke all on function public.rotate_api_key(uuid, integer) from public;
grant execute on function public.rotate_api_key(uuid, integer) to authenticated;

create or replace function public.update_api_key_settings(
  p_key_id uuid,
  p_scopes text[],
  p_allowed_cidrs cidr[],
  p_rate_limit_per_minute integer
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key public.api_keys;
begin
  select * into v_key from public.api_keys where id = p_key_id;
  if not found then
    raise exception 'API key not found';
  end if;
  if not public.has_org_role(v_key.organization_id, array['owner', 'admin']) then
    raise exception 'updating API keys requires the owner or admin role' using errcode = '42501';
  end if;
  if v_key.revoked_at is not null then
    raise exception 'revoked keys cannot be changed';
  end if;
  if not public.api_key_valid_scopes(p_scopes) then
    raise exception 'scopes must include ingest and may only contain ingest, ingest:content';
  end if;
  if coalesce(array_length(p_allowed_cidrs, 1), 0) > 20 then
    raise exception 'at most 20 allowed IP ranges per key';
  end if;
  if p_rate_limit_per_minute is null or p_rate_limit_per_minute < 1 or p_rate_limit_per_minute > 10000 then
    raise exception 'rate limit must be between 1 and 10000 requests per minute';
  end if;

  update public.api_keys
  set scopes = p_scopes,
      allowed_cidrs = coalesce(p_allowed_cidrs, '{}'),
      rate_limit_per_minute = p_rate_limit_per_minute
  where id = p_key_id;

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata
  ) values (
    v_key.organization_id, auth.uid(), 'user', 'api_key_updated', 'api_key', p_key_id, 'success',
    jsonb_build_object(
      'scopes', to_jsonb(p_scopes),
      'allowed_cidrs', to_jsonb(coalesce(p_allowed_cidrs, '{}')::text[]),
      'rate_limit_per_minute', p_rate_limit_per_minute
    )
  );

  return jsonb_build_object('id', p_key_id, 'updated', true);
end;
$$;

revoke all on function public.update_api_key_settings(uuid, text[], cidr[], integer) from public;
grant execute on function public.update_api_key_settings(uuid, text[], cidr[], integer) to authenticated;

-- Service-side gate used by ingest-event BEFORE evaluation: validity, scope,
-- and IP allow-list. Denials are audit-logged without exposing the key.
create or replace function public.authorize_api_key(
  p_key_hash text,
  p_client_ip text,
  p_required_scopes text[]
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key public.api_keys;
  v_ip inet;
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;

  select * into v_key from public.api_keys where key_hash = p_key_hash;
  if not found
     or v_key.revoked_at is not null
     or (v_key.expires_at is not null and v_key.expires_at <= now()) then
    return jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;

  if not (coalesce(p_required_scopes, '{}') <@ v_key.scopes) then
    insert into public.audit_logs (organization_id, actor_type, action, resource_type, resource_id, result, metadata)
    values (v_key.organization_id, 'system', 'api_key_scope_denied', 'api_key', v_key.id, 'denied',
            jsonb_build_object('required', to_jsonb(p_required_scopes), 'granted', to_jsonb(v_key.scopes)));
    return jsonb_build_object('ok', false, 'reason', 'scope', 'missing', to_jsonb(
      array(select s from unnest(p_required_scopes) s where not (s = any(v_key.scopes)))
    ));
  end if;

  begin
    v_ip := nullif(trim(p_client_ip), '')::inet;
  exception when others then
    v_ip := null;
  end;

  if coalesce(array_length(v_key.allowed_cidrs, 1), 0) > 0 then
    if v_ip is null or not exists (select 1 from unnest(v_key.allowed_cidrs) c where v_ip <<= c) then
      insert into public.audit_logs (organization_id, actor_type, action, resource_type, resource_id, result, metadata)
      values (v_key.organization_id, 'system', 'api_key_ip_denied', 'api_key', v_key.id, 'denied',
              jsonb_build_object('client_ip', host(v_ip)));
      return jsonb_build_object('ok', false, 'reason', 'ip');
    end if;
  end if;

  update public.api_keys
  set last_used_ip = v_ip, use_count = use_count + 1
  where id = v_key.id;

  return jsonb_build_object(
    'ok', true,
    'key_id', v_key.id,
    'organization_id', v_key.organization_id,
    'scopes', to_jsonb(v_key.scopes),
    'rate_limit_per_minute', v_key.rate_limit_per_minute
  );
end;
$$;

revoke all on function public.authorize_api_key(text, text, text[]) from public;
grant execute on function public.authorize_api_key(text, text, text[]) to service_role;

-- =====================================================================================
-- 4. Approval workflow
-- =====================================================================================
alter table public.approval_requests add column if not exists expires_at timestamptz;
alter table public.approval_requests add column if not exists escalation_level integer not null default 0;
alter table public.approval_requests add column if not exists escalated_at timestamptz;
alter table public.approval_requests add column if not exists assigned_to uuid references auth.users(id) on delete set null;

update public.approval_requests
set expires_at = created_at + interval '72 hours'
where expires_at is null;

alter table public.approval_requests alter column expires_at set default (now() + interval '72 hours');

alter table public.approval_requests drop constraint if exists approval_requests_escalation_range;
alter table public.approval_requests
  add constraint approval_requests_escalation_range check (escalation_level between 0 and 3);

create index if not exists idx_approval_requests_pending_expiry
  on public.approval_requests (expires_at) where status = 'pending';

create table if not exists public.approval_comments (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  approval_id uuid not null references public.approval_requests(id) on delete cascade,
  author_id uuid references auth.users(id) on delete set null,
  body text not null check (char_length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);

create index if not exists idx_approval_comments_approval on public.approval_comments (approval_id, created_at);

alter table public.approval_comments enable row level security;

drop policy if exists "approval_comments_select_member" on public.approval_comments;
create policy "approval_comments_select_member"
  on public.approval_comments for select
  using (public.is_org_member(organization_id));
-- Writes go through add_approval_comment (security definer) only.

-- Expire overdue approvals and auto-escalate ones waiting > 24h.
-- Callable by members (scoped to their org) or service_role / pg_cron (all orgs).
create or replace function public.expire_stale_approvals(p_organization_id uuid default null)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_expired integer := 0;
  v_escalated integer := 0;
  v_row record;
begin
  if auth.uid() is not null then
    if p_organization_id is null or not public.is_org_member(p_organization_id) then
      raise exception 'must be an organization member' using errcode = '42501';
    end if;
  end if;

  for v_row in
    update public.approval_requests
    set status = 'expired', decided_at = now(), note = coalesce(note, 'Expired without a decision')
    where status = 'pending'
      and expires_at is not null
      and expires_at <= now()
      and (p_organization_id is null or organization_id = p_organization_id)
    returning id, organization_id, ai_request_id
  loop
    v_expired := v_expired + 1;
    update public.ai_requests set status = 'blocked' where id = v_row.ai_request_id;
    insert into public.audit_logs (organization_id, actor_type, action, resource_type, resource_id, result, metadata)
    values (v_row.organization_id, 'system', 'approval_expired', 'approval_request', v_row.id, 'expired',
            jsonb_build_object('ai_request_id', v_row.ai_request_id));
  end loop;

  for v_row in
    update public.approval_requests
    set escalation_level = 1, escalated_at = now()
    where status = 'pending'
      and escalation_level = 0
      and created_at <= now() - interval '24 hours'
      and (p_organization_id is null or organization_id = p_organization_id)
    returning id, organization_id
  loop
    v_escalated := v_escalated + 1;
    insert into public.audit_logs (organization_id, actor_type, action, resource_type, resource_id, result, metadata)
    values (v_row.organization_id, 'system', 'approval_escalated', 'approval_request', v_row.id, 'escalated',
            jsonb_build_object('level', 1, 'automatic', true, 'reason', 'pending for more than 24 hours'));
  end loop;

  return jsonb_build_object('expired', v_expired, 'escalated', v_escalated);
end;
$$;

revoke all on function public.expire_stale_approvals(uuid) from public;
grant execute on function public.expire_stale_approvals(uuid) to authenticated, service_role;

create or replace function public.escalate_approval(p_approval_id uuid, p_note text default null)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_approval public.approval_requests;
  v_level integer;
begin
  select * into v_approval from public.approval_requests where id = p_approval_id;
  if not found then
    raise exception 'approval request not found';
  end if;
  if not public.is_org_member(v_approval.organization_id) then
    raise exception 'must be an organization member' using errcode = '42501';
  end if;
  if v_approval.status <> 'pending' then
    raise exception 'approval request is no longer pending';
  end if;
  if v_approval.escalation_level >= 3 then
    raise exception 'approval request is already at the highest escalation level';
  end if;
  if p_note is not null and char_length(p_note) > 500 then
    raise exception 'note must be at most 500 characters';
  end if;

  v_level := v_approval.escalation_level + 1;
  update public.approval_requests
  set escalation_level = v_level, escalated_at = now()
  where id = p_approval_id;

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata
  ) values (
    v_approval.organization_id, auth.uid(), 'user', 'approval_escalated', 'approval_request', p_approval_id,
    'escalated', jsonb_build_object('level', v_level, 'automatic', false, 'note', nullif(trim(p_note), ''))
  );

  return jsonb_build_object('approval_id', p_approval_id, 'escalation_level', v_level);
end;
$$;

revoke all on function public.escalate_approval(uuid, text) from public;
grant execute on function public.escalate_approval(uuid, text) to authenticated;

create or replace function public.delegate_approval(p_approval_id uuid, p_assignee uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_approval public.approval_requests;
begin
  select * into v_approval from public.approval_requests where id = p_approval_id;
  if not found then
    raise exception 'approval request not found';
  end if;
  if not public.has_org_role(v_approval.organization_id, array['owner', 'admin']) then
    raise exception 'delegating approvals requires the owner or admin role' using errcode = '42501';
  end if;
  if v_approval.status <> 'pending' then
    raise exception 'approval request is no longer pending';
  end if;
  if p_assignee is not null and not exists (
    select 1 from public.organization_members m
    where m.organization_id = v_approval.organization_id
      and m.user_id = p_assignee
      and m.status = 'active'
      and m.role in ('owner', 'admin', 'security')
  ) then
    raise exception 'assignee must be an active owner, admin, or security member';
  end if;

  update public.approval_requests set assigned_to = p_assignee where id = p_approval_id;

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata
  ) values (
    v_approval.organization_id, auth.uid(), 'user',
    case when p_assignee is null then 'approval_unassigned' else 'approval_delegated' end,
    'approval_request', p_approval_id, 'success',
    jsonb_build_object('assigned_to', p_assignee, 'previous_assignee', v_approval.assigned_to)
  );

  return jsonb_build_object('approval_id', p_approval_id, 'assigned_to', p_assignee);
end;
$$;

revoke all on function public.delegate_approval(uuid, uuid) from public;
grant execute on function public.delegate_approval(uuid, uuid) to authenticated;

create or replace function public.add_approval_comment(p_approval_id uuid, p_body text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_approval public.approval_requests;
  v_id uuid;
begin
  select * into v_approval from public.approval_requests where id = p_approval_id;
  if not found then
    raise exception 'approval request not found';
  end if;
  if not public.is_org_member(v_approval.organization_id) then
    raise exception 'must be an organization member' using errcode = '42501';
  end if;
  if p_body is null or char_length(trim(p_body)) = 0 or char_length(p_body) > 2000 then
    raise exception 'comment must be 1-2000 characters';
  end if;

  insert into public.approval_comments (organization_id, approval_id, author_id, body)
  values (v_approval.organization_id, p_approval_id, auth.uid(), trim(p_body))
  returning id into v_id;

  insert into public.audit_logs (
    organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata
  ) values (
    v_approval.organization_id, auth.uid(), 'user', 'approval_commented', 'approval_request', p_approval_id,
    'success', jsonb_build_object('comment_id', v_id, 'length', char_length(trim(p_body)))
  );

  return jsonb_build_object('comment_id', v_id);
end;
$$;

revoke all on function public.add_approval_comment(uuid, text) from public;
grant execute on function public.add_approval_comment(uuid, text) to authenticated;

-- Full timeline for one approval: audit events + comments, with author names.
create or replace function public.get_approval_timeline(p_approval_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.approval_requests where id = p_approval_id;
  if v_org is null then
    raise exception 'approval request not found';
  end if;
  if not public.is_org_member(v_org) then
    raise exception 'must be an organization member' using errcode = '42501';
  end if;

  return coalesce((
    select jsonb_agg(item order by (item ->> 'at'))
    from (
      select jsonb_build_object(
        'kind', 'event',
        'id', a.id,
        'action', a.action,
        'actor_type', a.actor_type,
        'actor_name', p.full_name,
        'metadata', a.metadata - 'note',
        'note', a.metadata ->> 'note',
        'at', a.created_at
      ) as item
      from public.audit_logs a
      left join public.profiles p on p.id = a.actor_user_id
      where a.resource_type = 'approval_request' and a.resource_id = p_approval_id
        and a.action <> 'approval_commented'
      union all
      select jsonb_build_object(
        'kind', 'comment',
        'id', c.id,
        'actor_name', p.full_name,
        'body', c.body,
        'at', c.created_at
      )
      from public.approval_comments c
      left join public.profiles p on p.id = c.author_id
      where c.approval_id = p_approval_id
    ) timeline
  ), '[]'::jsonb);
end;
$$;

revoke all on function public.get_approval_timeline(uuid) from public;
grant execute on function public.get_approval_timeline(uuid) to authenticated;

-- decide_approval: same signature, now enforces expiry and honours delegation.
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
  v_via_delegation boolean := false;
begin
  if p_decision not in ('approved', 'rejected') then
    raise exception 'decision must be approved or rejected';
  end if;
  if p_note is not null and char_length(p_note) > 1000 then
    raise exception 'note must be at most 1000 characters';
  end if;

  select * into v_approval
  from public.approval_requests
  where id = p_approval_id
  for update;
  if not found then
    raise exception 'approval request not found';
  end if;
  if v_approval.status <> 'pending' then
    raise exception 'approval request is no longer pending';
  end if;
  if v_approval.expires_at is not null and v_approval.expires_at <= now() then
    raise exception 'approval request has expired';
  end if;

  if not public.has_org_role(v_approval.organization_id, array['owner', 'admin']) then
    if v_approval.assigned_to = auth.uid()
       and public.has_org_role(v_approval.organization_id, array['security']) then
      v_via_delegation := true;
    else
      raise exception 'only organization owners, admins, or the delegated reviewer can decide approvals'
        using errcode = '42501';
    end if;
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
      'self_approved', v_approval.requested_by = auth.uid(),
      'via_delegation', v_via_delegation,
      'escalation_level', v_approval.escalation_level
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

-- =====================================================================================
-- 5. Monitoring
-- =====================================================================================
create table if not exists public.request_metrics (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  ai_request_id uuid references public.ai_requests(id) on delete set null,
  source text not null check (source in ('gateway', 'ingest')),
  provider text,
  model text,
  outcome text not null
    check (outcome in ('allowed', 'blocked', 'review', 'error', 'rate_limited', 'denied')),
  status_code integer,
  latency_ms integer check (latency_ms is null or latency_ms >= 0),
  provider_latency_ms integer check (provider_latency_ms is null or provider_latency_ms >= 0),
  attempts integer not null default 1,
  fallback_used boolean not null default false,
  input_tokens integer,
  output_tokens integer,
  cost_usd numeric(14, 6),
  error_code text,
  output_findings jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_request_metrics_org_created on public.request_metrics (organization_id, created_at desc);

alter table public.request_metrics enable row level security;

drop policy if exists "request_metrics_select_member" on public.request_metrics;
create policy "request_metrics_select_member"
  on public.request_metrics for select
  using (public.is_org_member(organization_id));
-- Written by edge functions with the service role only.

create or replace function public.get_monitoring_summary(p_organization_id uuid, p_hours integer default 24)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_since timestamptz;
  v_totals jsonb;
  v_latency jsonb;
  v_series jsonb;
  v_providers jsonb;
  v_alerts jsonb := '[]'::jsonb;
  v_requests integer;
  v_errors integer;
  v_denied integer;
  v_rate_limited integer;
  v_p95 numeric;
  v_expiring integer;
  v_escalated integer;
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'must be an organization member' using errcode = '42501';
  end if;
  if p_hours is null or p_hours < 1 or p_hours > 720 then
    raise exception 'window must be between 1 and 720 hours';
  end if;
  v_since := now() - make_interval(hours => p_hours);

  select
    count(*)::int,
    count(*) filter (where outcome = 'error')::int,
    count(*) filter (where outcome in ('blocked', 'denied'))::int,
    count(*) filter (where outcome = 'rate_limited')::int,
    jsonb_build_object(
      'requests', count(*),
      'allowed', count(*) filter (where outcome = 'allowed'),
      'blocked', count(*) filter (where outcome = 'blocked'),
      'review', count(*) filter (where outcome = 'review'),
      'errors', count(*) filter (where outcome = 'error'),
      'rate_limited', count(*) filter (where outcome = 'rate_limited'),
      'denied', count(*) filter (where outcome = 'denied'),
      'fallbacks', count(*) filter (where fallback_used),
      'output_redactions', count(*) filter (where jsonb_array_length(output_findings) > 0),
      'input_tokens', coalesce(sum(input_tokens), 0),
      'output_tokens', coalesce(sum(output_tokens), 0),
      'cost_usd', coalesce(round(sum(cost_usd), 4), 0)
    )
  into v_requests, v_errors, v_denied, v_rate_limited, v_totals
  from public.request_metrics
  where organization_id = p_organization_id and created_at >= v_since;

  select
    percentile_cont(0.95) within group (order by latency_ms),
    jsonb_build_object(
      'p50', round(percentile_cont(0.5) within group (order by latency_ms)::numeric),
      'p95', round(percentile_cont(0.95) within group (order by latency_ms)::numeric),
      'p99', round(percentile_cont(0.99) within group (order by latency_ms)::numeric),
      'provider_p95', round(percentile_cont(0.95) within group (order by provider_latency_ms)::numeric)
    )
  into v_p95, v_latency
  from public.request_metrics
  where organization_id = p_organization_id and created_at >= v_since and latency_ms is not null;

  select coalesce(jsonb_agg(row_to_json(s) order by s.bucket), '[]'::jsonb) into v_series
  from (
    select
      date_trunc('hour', created_at) as bucket,
      count(*)::int as requests,
      count(*) filter (where outcome = 'error')::int as errors,
      count(*) filter (where outcome in ('blocked', 'denied'))::int as blocked,
      count(*) filter (where outcome = 'rate_limited')::int as rate_limited,
      round(coalesce(percentile_cont(0.95) within group (order by latency_ms), 0)::numeric) as p95_ms
    from public.request_metrics
    where organization_id = p_organization_id and created_at >= v_since
    group by 1
  ) s;

  select coalesce(jsonb_agg(row_to_json(pr) order by pr.requests desc), '[]'::jsonb) into v_providers
  from (
    select
      coalesce(provider, 'ingest') as provider,
      count(*)::int as requests,
      count(*) filter (where outcome = 'error')::int as errors,
      round(coalesce(percentile_cont(0.95) within group (order by provider_latency_ms), 0)::numeric) as p95_ms,
      coalesce(round(sum(cost_usd), 4), 0) as cost_usd
    from public.request_metrics
    where organization_id = p_organization_id and created_at >= v_since
    group by 1
  ) pr;

  select
    count(*) filter (where expires_at <= now() + interval '6 hours')::int,
    count(*) filter (where escalation_level > 0)::int
  into v_expiring, v_escalated
  from public.approval_requests
  where organization_id = p_organization_id and status = 'pending';

  if v_requests >= 20 and v_errors::numeric / v_requests > 0.05 then
    v_alerts := v_alerts || jsonb_build_object('severity', 'critical', 'code', 'error_rate',
      'message', format('Error rate is %s%% over the last %s hours.', round(v_errors * 100.0 / v_requests, 1), p_hours));
  end if;
  if v_p95 is not null and v_p95 > 10000 then
    v_alerts := v_alerts || jsonb_build_object('severity', 'warning', 'code', 'latency',
      'message', format('p95 latency is %s ms (threshold 10000 ms).', round(v_p95)));
  end if;
  if v_requests >= 20 and v_denied::numeric / v_requests > 0.5 then
    v_alerts := v_alerts || jsonb_build_object('severity', 'warning', 'code', 'denial_spike',
      'message', format('%s%% of requests were blocked or denied — check for misconfigured policies or abuse.',
        round(v_denied * 100.0 / v_requests, 1)));
  end if;
  if v_rate_limited > 0 then
    v_alerts := v_alerts || jsonb_build_object('severity', 'info', 'code', 'rate_limited',
      'message', format('%s requests were rate limited.', v_rate_limited));
  end if;
  if v_expiring > 0 then
    v_alerts := v_alerts || jsonb_build_object('severity', 'warning', 'code', 'approvals_expiring',
      'message', format('%s pending approvals expire within 6 hours.', v_expiring));
  end if;
  if v_escalated > 0 then
    v_alerts := v_alerts || jsonb_build_object('severity', 'info', 'code', 'approvals_escalated',
      'message', format('%s pending approvals are escalated.', v_escalated));
  end if;

  return jsonb_build_object(
    'window_hours', p_hours,
    'totals', v_totals,
    'latency', coalesce(v_latency, jsonb_build_object('p50', null, 'p95', null, 'p99', null, 'provider_p95', null)),
    'error_rate', case when v_requests > 0 then round(v_errors::numeric / v_requests, 4) else 0 end,
    'denial_rate', case when v_requests > 0 then round(v_denied::numeric / v_requests, 4) else 0 end,
    'timeseries', v_series,
    'providers', v_providers,
    'alerts', v_alerts
  );
end;
$$;

revoke all on function public.get_monitoring_summary(uuid, integer) from public;
grant execute on function public.get_monitoring_summary(uuid, integer) to authenticated;
