-- 018_dashboard_graphs.sql
-- New dashboard aggregates behind the "Riskiest agents" and "What we're
-- catching" panels: per-agent block counts and detection-category hits.
-- Both are security-definer reads guarded by org membership, matching the
-- existing dashboard RPCs in 008_functions.sql.

create or replace function public.get_risky_agents(p_organization_id uuid, p_days integer default 7)
returns table (agent text, requests bigint, blocked bigint)
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
    coalesce(a.name, 'Unknown agent'),
    count(r.id),
    count(r.id) filter (where r.status = 'blocked')
  from public.ai_requests r
  left join public.ai_agents a on a.id = r.agent_id
  where r.organization_id = p_organization_id
    and r.created_at >= now() - (p_days || ' days')::interval
  group by a.name
  order by count(r.id) filter (where r.status = 'blocked') desc, count(r.id) desc
  limit 8;
end;
$$;

grant execute on function public.get_risky_agents(uuid, integer) to authenticated;

create or replace function public.get_detection_categories(p_organization_id uuid, p_days integer default 7)
returns table (category text, hits bigint)
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
    f.value ->> 'category',
    count(*)
  from public.ai_requests r,
    jsonb_array_elements(coalesce(r.metadata -> 'detections', '[]'::jsonb)) as f(value)
  where r.organization_id = p_organization_id
    and r.created_at >= now() - (p_days || ' days')::interval
    and f.value ->> 'category' is not null
  group by f.value ->> 'category'
  order by count(*) desc
  limit 10;
end;
$$;

grant execute on function public.get_detection_categories(uuid, integer) to authenticated;
