-- 022_monitoring.sql
-- Production monitoring: per-invocation function metrics plus alert rules /
-- alerts evaluated by the monitoring-check edge function.
--
-- Writes to function_metrics go ONLY through the record_function_metric()
-- SECURITY DEFINER RPC (wired to _shared/metrics.ts, which is fire-and-forget),
-- so a metrics outage can never fail a real request. There are no
-- insert/update/delete RLS policies on the table at all.

create extension if not exists "pgcrypto";

-- Raw per-invocation metrics ---------------------------------------------------
create table public.function_metrics (
  id uuid primary key default gen_random_uuid(),
  function_name text not null,
  organization_id uuid,
  status text not null check (status in ('ok', 'error', 'rate_limited')),
  latency_ms int not null,
  error_code text,
  created_at timestamptz not null default now()
);

create index function_metrics_function_created_idx
  on public.function_metrics (function_name, created_at desc);
create index function_metrics_org_created_idx
  on public.function_metrics (organization_id, created_at desc);

alter table public.function_metrics enable row level security;

-- Members read their own org's rows. Rows with a NULL organization_id (metrics
-- recorded before the org was known) match no membership and are readable by
-- nobody except service_role, which bypasses RLS.
create policy "metrics_select_member"
  on public.function_metrics for select
  using (public.is_org_member(organization_id));

-- Intentionally no insert/update/delete policies: writes happen only through
-- the RPC below.

create or replace function public.record_function_metric(
  p_function_name text,
  p_organization_id uuid,
  p_status text,
  p_latency_ms int,
  p_error_code text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_status is null or p_status not in ('ok', 'error', 'rate_limited') then
    raise exception 'invalid metric status: %', coalesce(p_status, 'null');
  end if;
  insert into public.function_metrics (function_name, organization_id, status, latency_ms, error_code)
  values (p_function_name, p_organization_id, p_status, p_latency_ms, p_error_code);
end;
$$;

grant execute on function public.record_function_metric(text, uuid, text, int, text)
  to anon, authenticated, service_role;

-- Alert rules (owner/admin managed) ---------------------------------------------
create table public.alert_rules (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null,
  name text not null,
  metric text not null check (metric in ('error_rate', 'p95_latency_ms', 'denial_rate', 'provider_failures')),
  threshold numeric not null,
  window_minutes int not null default 60,
  is_active bool not null default true,
  created_at timestamptz not null default now()
);

alter table public.alert_rules enable row level security;

create policy "alert_rules_select_member"
  on public.alert_rules for select
  using (public.is_org_member(organization_id));

create policy "alert_rules_insert_privileged"
  on public.alert_rules for insert
  with check (public.has_org_role(organization_id, array['owner', 'admin']));

create policy "alert_rules_update_privileged"
  on public.alert_rules for update
  using (public.has_org_role(organization_id, array['owner', 'admin']))
  with check (public.has_org_role(organization_id, array['owner', 'admin']));

create policy "alert_rules_delete_privileged"
  on public.alert_rules for delete
  using (public.has_org_role(organization_id, array['owner', 'admin']));

-- Alerts (written only by the monitoring check; members read) -------------------
create table public.alerts (
  id uuid primary key default gen_random_uuid(),
  rule_id uuid not null references public.alert_rules (id) on delete cascade,
  organization_id uuid not null,
  message text not null,
  severity text not null default 'warning' check (severity in ('info', 'warning', 'critical')),
  status text not null default 'firing' check (status in ('firing', 'resolved')),
  fired_at timestamptz not null default now(),
  resolved_at timestamptz
);

create index alerts_org_status_idx
  on public.alerts (organization_id, status);

alter table public.alerts enable row level security;

create policy "alerts_select_member"
  on public.alerts for select
  using (public.is_org_member(organization_id));

-- Intentionally no insert/update/delete policies: only the monitoring-check
-- edge function (service role, bypasses RLS) writes alerts.

-- Rule evaluation --------------------------------------------------------------
-- Computes one alert rule's metric over its trailing window and fires or
-- resolves the alert accordingly. Called by the monitoring-check edge function
-- (service role). Kept as SQL so the aggregations (percentile_cont for p95)
-- run in the database rather than pulling raw rows over the wire.
create or replace function public.check_alert_rule(p_rule_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_rule public.alert_rules%rowtype;
  v_since timestamptz;
  v_total bigint := 0;
  v_value numeric;
  v_breach boolean := false;
  v_existing uuid;
  v_severity text;
  v_message text;
  v_fired boolean := false;
  v_resolved boolean := false;
  v_resolved_count int := 0;
begin
  select * into v_rule
  from public.alert_rules ar
  where ar.id = p_rule_id and ar.is_active;

  if not found then
    return jsonb_build_object(
      'rule_id', p_rule_id,
      'checked', false,
      'reason', 'rule not found or inactive'
    );
  end if;

  v_since := now() - make_interval(mins => v_rule.window_minutes);

  if v_rule.metric = 'error_rate' then
    select count(*),
           case when count(*) = 0 then 0
                else count(*) filter (where fm.status = 'error')::numeric / count(*)
           end
    into v_total, v_value
    from public.function_metrics fm
    where fm.organization_id = v_rule.organization_id
      and fm.created_at >= v_since;
    v_breach := v_total > 0 and v_value > v_rule.threshold;

  elsif v_rule.metric = 'denial_rate' then
    select count(*),
           case when count(*) = 0 then 0
                else count(*) filter (where fm.status = 'rate_limited')::numeric / count(*)
           end
    into v_total, v_value
    from public.function_metrics fm
    where fm.organization_id = v_rule.organization_id
      and fm.created_at >= v_since;
    v_breach := v_total > 0 and v_value > v_rule.threshold;

  elsif v_rule.metric = 'p95_latency_ms' then
    select percentile_cont(0.95) within group (order by fm.latency_ms)
    into v_value
    from public.function_metrics fm
    where fm.organization_id = v_rule.organization_id
      and fm.created_at >= v_since;
    v_breach := v_value is not null and v_value > v_rule.threshold;

  elsif v_rule.metric = 'provider_failures' then
    select count(*)::numeric
    into v_value
    from public.function_metrics fm
    where fm.organization_id = v_rule.organization_id
      and fm.created_at >= v_since
      and fm.status = 'error'
      and fm.function_name = 'ai-gateway';
    v_breach := v_value > v_rule.threshold;

  else
    return jsonb_build_object(
      'rule_id', p_rule_id,
      'checked', false,
      'reason', 'unknown metric'
    );
  end if;

  if v_breach then
    select a.id into v_existing
    from public.alerts a
    where a.rule_id = v_rule.id and a.status = 'firing'
    limit 1;

    if v_existing is null then
      v_severity := case
        when v_rule.metric in ('provider_failures', 'error_rate') then 'critical'
        else 'warning'
      end;
      v_message := format(
        '%s: %s measured %s vs threshold %s over the last %s minute(s)',
        v_rule.name, v_rule.metric, v_value, v_rule.threshold, v_rule.window_minutes
      );
      insert into public.alerts (rule_id, organization_id, message, severity)
      values (v_rule.id, v_rule.organization_id, v_message, v_severity);
      v_fired := true;
    end if;
  else
    update public.alerts
    set status = 'resolved', resolved_at = now()
    where rule_id = v_rule.id and status = 'firing';
    get diagnostics v_resolved_count = row_count;
    v_resolved := v_resolved_count > 0;
  end if;

  return jsonb_build_object(
    'rule_id', p_rule_id,
    'checked', true,
    'breached', v_breach,
    'value', v_value,
    'fired', v_fired,
    'resolved', v_resolved
  );
end;
$$;

grant execute on function public.check_alert_rule(uuid) to service_role;
