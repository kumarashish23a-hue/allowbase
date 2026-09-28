-- 021_policy_versions.sql
-- Policy versioning: every policy carries a monotonically increasing version
-- number, and every meaningful edit leaves an immutable snapshot in
-- public.policy_versions. policy_versions is append-only: the ONLY select
-- policy is permissive, so snapshots are written exclusively by the
-- SECURITY DEFINER trigger / rollback function, which bypass RLS.

-- 1. Version column on policies ----------------------------------------------
alter table public.policies
  add column if not exists version int not null default 1;

-- 2. Snapshot table ------------------------------------------------------------
create table public.policy_versions (
  id uuid primary key default gen_random_uuid(),
  policy_id uuid not null references public.policies(id) on delete cascade
    -- Deferred so the snapshot trigger (which fires BEFORE the policy row is
    -- stored) can write its row inside the same statement.
    deferrable initially deferred,
  organization_id uuid not null,
  version int not null,
  name text,
  description text,
  rule jsonb,
  action text,
  priority int,
  status text,
  change_note text,
  published_by uuid references auth.users(id),
  published_at timestamptz not null default now(),
  constraint policy_versions_unique unique (policy_id, version)
);

create index idx_policy_versions_policy
  on public.policy_versions (policy_id, version desc);

-- Append-only: members can read snapshots for their own organizations.
-- No insert/update/delete policies exist, so direct client writes are denied;
-- only the SECURITY DEFINER trigger and rollback function can write rows.
alter table public.policy_versions enable row level security;

create policy "policy_versions_select_member"
  on public.policy_versions for select
  using (public.is_org_member(organization_id));

-- 3. Snapshot trigger -----------------------------------------------------------
-- SECURITY DEFINER so it can write to policy_versions (which has no
-- insert policy for clients). search_path is pinned and refs are qualified.
create or replace function public.snapshot_policy_version()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_changed boolean;
begin
  if TG_OP = 'INSERT' then
    new.version := 1;
    insert into public.policy_versions
      (policy_id, organization_id, version, name, description, rule,
       action, priority, status, change_note, published_by)
    values
      (new.id, new.organization_id, 1, new.name, new.description, new.rule,
       new.action, new.priority, new.status, null, auth.uid());
    return new;
  end if;

  -- UPDATE: only snapshot when a meaningful field changed. updated_at
  -- touches (via the policies_set_updated_at trigger) must not bump.
  v_changed := (new.name is distinct from old.name)
        or (new.description is distinct from old.description)
        or (new.rule is distinct from old.rule)
        or (new.action is distinct from old.action)
        or (new.priority is distinct from old.priority)
        or (new.status is distinct from old.status);

  if v_changed then
    new.version := old.version + 1;
    insert into public.policy_versions
      (policy_id, organization_id, version, name, description, rule,
       action, priority, status, change_note, published_by)
    values
      (new.id, new.organization_id, new.version, new.name, new.description,
       new.rule, new.action, new.priority, new.status, null, auth.uid());
  end if;

  return new;
end;
$$;

-- Runs BEFORE the existing policies_set_updated_at trigger (created first),
-- so version snapshots compare against the real row values.
create trigger policies_snapshot_version
  before insert or update on public.policies
  for each row execute function public.snapshot_policy_version();

-- 4. Backfill: snapshot the current state of pre-existing policies -------------
insert into public.policy_versions
  (policy_id, organization_id, version, name, description, rule,
   action, priority, status, change_note)
select
  p.id, p.organization_id, p.version, p.name, p.description, p.rule,
  p.action, p.priority, p.status, 'Initial version (backfill)'
from public.policies p
where not exists (
  select 1 from public.policy_versions pv
  where pv.policy_id = p.id
);

-- 5. Rollback --------------------------------------------------------------------
-- Restores a policy to a previous snapshot version. SECURITY DEFINER so the
-- snapshot write (and read of the target snapshot) succeeds for authorized
-- users; authorization is enforced explicitly below.
create or replace function public.rollback_policy(
  p_policy_id uuid,
  p_to_version int,
  p_note text
)
returns int
language plpgsql
security definer
set search_path = public
as $$
declare
  v_org_id uuid;
  v_role text;
  v_target record;
  v_old_version int;
  v_new_version int;
begin
  select organization_id into v_org_id
  from public.policies
  where id = p_policy_id;
  if not found then
    raise exception 'not_found';
  end if;

  select m.role into v_role
  from public.organization_members m
  where m.organization_id = v_org_id
    and m.user_id = auth.uid()
    and m.status = 'active'
  limit 1;
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'not_authorized';
  end if;

  select * into v_target
  from public.policy_versions
  where policy_id = p_policy_id
    and version = p_to_version;
  if not found then
    raise exception 'version_not_found';
  end if;

  select version into v_old_version
  from public.policies
  where id = p_policy_id;

  -- Restore the meaningful fields; the snapshot trigger fires, bumps the
  -- version, and writes a new snapshot row.
  update public.policies
  set name = v_target.name,
      description = v_target.description,
      rule = v_target.rule,
      action = v_target.action,
      priority = v_target.priority,
      status = v_target.status
  where id = p_policy_id;

  v_new_version := v_old_version + 1;

  -- Attach the change note to the snapshot just written by the trigger.
  update public.policy_versions
  set change_note = p_note
  where policy_id = p_policy_id
    and version = v_new_version;

  return v_new_version;
end;
$$;

grant execute on function public.rollback_policy(uuid, int, text) to authenticated;
