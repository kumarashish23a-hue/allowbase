-- 007_rls.sql
-- Row Level Security: users only ever see data for organizations they belong to.

-- Membership helpers ----------------------------------------------------------
create or replace function public.is_org_member(org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.organization_members m
    where m.organization_id = org_id
      and m.user_id = auth.uid()
      and m.status = 'active'
  );
$$;

create or replace function public.org_role(org_id uuid)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select m.role
  from public.organization_members m
  where m.organization_id = org_id
    and m.user_id = auth.uid()
    and m.status = 'active'
  limit 1;
$$;

create or replace function public.has_org_role(org_id uuid, allowed text[])
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.org_role(org_id) = any (allowed);
$$;

grant execute on function public.is_org_member(uuid) to authenticated;
grant execute on function public.org_role(uuid) to authenticated;
grant execute on function public.has_org_role(uuid, text[]) to authenticated;

-- Enable RLS everywhere --------------------------------------------------------
alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.profiles enable row level security;
alter table public.data_sources enable row level security;
alter table public.data_assets enable row level security;
alter table public.sensitive_data_findings enable row level security;
alter table public.ai_models enable row level security;
alter table public.ai_agents enable row level security;
alter table public.ai_agent_data_permissions enable row level security;
alter table public.policies enable row level security;
alter table public.ai_requests enable row level security;
alter table public.ai_request_data enable row level security;
alter table public.policy_evaluations enable row level security;
alter table public.risk_events enable row level security;
alter table public.audit_logs enable row level security;

-- Organizations -----------------------------------------------------------------
create policy "org_select_member"
  on public.organizations for select
  using (public.is_org_member(id));

create policy "org_insert_authenticated"
  on public.organizations for insert
  with check (auth.uid() is not null);

create policy "org_update_privileged"
  on public.organizations for update
  using (public.has_org_role(id, array['owner', 'admin']))
  with check (public.has_org_role(id, array['owner', 'admin']));

create policy "org_delete_owner"
  on public.organizations for delete
  using (public.has_org_role(id, array['owner']));

-- Organization members ------------------------------------------------------------
create policy "members_select_member"
  on public.organization_members for select
  using (public.is_org_member(organization_id));

create policy "members_write_privileged"
  on public.organization_members for insert
  with check (public.has_org_role(organization_id, array['owner', 'admin']));

create policy "members_update_privileged"
  on public.organization_members for update
  using (public.has_org_role(organization_id, array['owner', 'admin']))
  with check (public.has_org_role(organization_id, array['owner', 'admin']));

create policy "members_delete_owner"
  on public.organization_members for delete
  using (public.has_org_role(organization_id, array['owner']));

-- Profiles -------------------------------------------------------------------------
-- Users manage their own profile. Cross-org profile reads are intentionally
-- not granted in this MVP.
create policy "profiles_select_own"
  on public.profiles for select
  using (id = auth.uid());

create policy "profiles_update_own"
  on public.profiles for update
  using (id = auth.uid())
  with check (id = auth.uid());

-- Data sources -----------------------------------------------------------------------
create policy "sources_select_member"
  on public.data_sources for select
  using (public.is_org_member(organization_id));

create policy "sources_write_privileged"
  on public.data_sources for insert
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "sources_update_privileged"
  on public.data_sources for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "sources_delete_privileged"
  on public.data_sources for delete
  using (public.has_org_role(organization_id, array['owner', 'admin']));

-- Data assets --------------------------------------------------------------------------
create policy "assets_select_member"
  on public.data_assets for select
  using (public.is_org_member(organization_id));

create policy "assets_write_privileged"
  on public.data_assets for insert
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "assets_update_privileged"
  on public.data_assets for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "assets_delete_privileged"
  on public.data_assets for delete
  using (public.has_org_role(organization_id, array['owner', 'admin']));

-- Sensitive findings ----------------------------------------------------------------------
create policy "findings_select_member"
  on public.sensitive_data_findings for select
  using (public.is_org_member(organization_id));

create policy "findings_write_privileged"
  on public.sensitive_data_findings for insert
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "findings_update_privileged"
  on public.sensitive_data_findings for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "findings_delete_privileged"
  on public.sensitive_data_findings for delete
  using (public.has_org_role(organization_id, array['owner', 'admin']));

-- AI models ---------------------------------------------------------------------------------
create policy "models_select_member"
  on public.ai_models for select
  using (public.is_org_member(organization_id));

create policy "models_write_privileged"
  on public.ai_models for insert
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "models_update_privileged"
  on public.ai_models for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "models_delete_privileged"
  on public.ai_models for delete
  using (public.has_org_role(organization_id, array['owner', 'admin']));

-- AI agents -----------------------------------------------------------------------------------
create policy "agents_select_member"
  on public.ai_agents for select
  using (public.is_org_member(organization_id));

create policy "agents_write_privileged"
  on public.ai_agents for insert
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security', 'developer']));

create policy "agents_update_privileged"
  on public.ai_agents for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security', 'developer']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security', 'developer']));

create policy "agents_delete_privileged"
  on public.ai_agents for delete
  using (public.has_org_role(organization_id, array['owner', 'admin']));

-- Agent data permissions (scoped through the parent agent) ---------------------------------------
create policy "agent_perms_select_member"
  on public.ai_agent_data_permissions for select
  using (
    exists (
      select 1 from public.ai_agents a
      where a.id = agent_id and public.is_org_member(a.organization_id)
    )
  );

create policy "agent_perms_write_privileged"
  on public.ai_agent_data_permissions for insert
  with check (
    exists (
      select 1 from public.ai_agents a
      where a.id = agent_id
        and public.has_org_role(a.organization_id, array['owner', 'admin', 'security'])
    )
  );

create policy "agent_perms_delete_privileged"
  on public.ai_agent_data_permissions for delete
  using (
    exists (
      select 1 from public.ai_agents a
      where a.id = agent_id
        and public.has_org_role(a.organization_id, array['owner', 'admin'])
    )
  );

-- Policies ------------------------------------------------------------------------------------------
create policy "policies_select_member"
  on public.policies for select
  using (public.is_org_member(organization_id));

create policy "policies_write_privileged"
  on public.policies for insert
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "policies_update_privileged"
  on public.policies for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

create policy "policies_delete_privileged"
  on public.policies for delete
  using (public.has_org_role(organization_id, array['owner', 'admin']));

-- AI requests --------------------------------------------------------------------------------------------
create policy "requests_select_member"
  on public.ai_requests for select
  using (public.is_org_member(organization_id));

-- Any active member may log an AI request; evaluation happens server-side.
create policy "requests_insert_member"
  on public.ai_requests for insert
  with check (public.is_org_member(organization_id));

create policy "requests_update_privileged"
  on public.ai_requests for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

-- Request data + evaluations (scoped through the parent request) ----------------------------------------------
create policy "request_data_select_member"
  on public.ai_request_data for select
  using (
    exists (
      select 1 from public.ai_requests r
      where r.id = ai_request_id and public.is_org_member(r.organization_id)
    )
  );

create policy "request_data_insert_member"
  on public.ai_request_data for insert
  with check (
    exists (
      select 1 from public.ai_requests r
      where r.id = ai_request_id and public.is_org_member(r.organization_id)
    )
  );

create policy "evaluations_select_member"
  on public.policy_evaluations for select
  using (
    exists (
      select 1 from public.ai_requests r
      where r.id = ai_request_id and public.is_org_member(r.organization_id)
    )
  );

create policy "evaluations_insert_member"
  on public.policy_evaluations for insert
  with check (
    exists (
      select 1 from public.ai_requests r
      where r.id = ai_request_id and public.is_org_member(r.organization_id)
    )
  );

-- Risk events ------------------------------------------------------------------------------------------------------
create policy "risks_select_member"
  on public.risk_events for select
  using (public.is_org_member(organization_id));

create policy "risks_insert_member"
  on public.risk_events for insert
  with check (public.is_org_member(organization_id));

create policy "risks_update_privileged"
  on public.risk_events for update
  using (public.has_org_role(organization_id, array['owner', 'admin', 'security']))
  with check (public.has_org_role(organization_id, array['owner', 'admin', 'security']));

-- Audit logs: append-only. Members may read and insert; nobody may update or delete. --------------------------------
create policy "audit_select_member"
  on public.audit_logs for select
  using (public.is_org_member(organization_id));

create policy "audit_insert_member"
  on public.audit_logs for insert
  with check (public.is_org_member(organization_id));
