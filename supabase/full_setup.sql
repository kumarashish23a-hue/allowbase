-- Data Control Plane: full backend setup (migrations 001-010 combined)
-- Paste this entire file into Supabase Dashboard > SQL Editor > New query and click Run.


-- =============================================================================
-- supabase/migrations/001_core.sql
-- =============================================================================
-- 001_core.sql
-- Extensions, shared triggers, organizations, organization members, profiles.

create extension if not exists "pgcrypto";

-- Keep updated_at fresh on every update.
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- Organizations -------------------------------------------------------------
create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  plan text not null default 'free'
    check (plan in ('free', 'startup', 'business', 'enterprise')),
  status text not null default 'active'
    check (status in ('active', 'suspended', 'archived')),
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create trigger organizations_set_updated_at
  before update on public.organizations
  for each row execute function public.set_updated_at();

-- Organization members ------------------------------------------------------
-- user_id intentionally has no FK to auth.users so demo/seed members and
-- service-managed identities can exist without a login.
create table public.organization_members (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null,
  role text not null default 'viewer'
    check (role in ('owner', 'admin', 'security', 'developer', 'analyst', 'viewer')),
  status text not null default 'active'
    check (status in ('active', 'invited', 'suspended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, user_id)
);

create index idx_org_members_organization on public.organization_members (organization_id);
create index idx_org_members_user on public.organization_members (user_id);

create trigger organization_members_set_updated_at
  before update on public.organization_members
  for each row execute function public.set_updated_at();

-- User profiles --------------------------------------------------------------
-- Supabase Auth owns credentials; this table only stores profile attributes.
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  avatar_url text,
  job_title text,
  department text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute function public.set_updated_at();

-- Automatically create a profile when a user signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, avatar_url)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', new.email),
    new.raw_user_meta_data ->> 'avatar_url'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- =============================================================================
-- supabase/migrations/002_data.sql
-- =============================================================================
-- 002_data.sql
-- Data sources, data assets, sensitive data findings.

-- Data sources ---------------------------------------------------------------
create table public.data_sources (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  type text not null
    check (type in ('google_drive', 'github', 'postgresql', 'slack', 'notion', 'aws_s3', 'crm', 'custom')),
  status text not null default 'demo'
    check (status in ('connected', 'disconnected', 'error', 'demo')),
  description text,
  external_id text,
  metadata jsonb not null default '{}'::jsonb,
  last_scan_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index idx_data_sources_org on public.data_sources (organization_id);
create index idx_data_sources_org_type on public.data_sources (organization_id, type);

create trigger data_sources_set_updated_at
  before update on public.data_sources
  for each row execute function public.set_updated_at();

-- Data assets ----------------------------------------------------------------
create table public.data_assets (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  data_source_id uuid references public.data_sources(id) on delete set null,
  name text not null,
  asset_type text not null
    check (asset_type in ('file', 'database', 'table', 'repository', 'channel', 'document', 'record', 'bucket')),
  classification text not null default 'internal'
    check (classification in ('public', 'internal', 'confidential', 'restricted')),
  sensitivity_level text not null default 'none'
    check (sensitivity_level in ('none', 'low', 'medium', 'high', 'critical')),
  owner_user_id uuid,
  metadata jsonb not null default '{}'::jsonb,
  last_scanned_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index idx_data_assets_org on public.data_assets (organization_id);
create index idx_data_assets_source on public.data_assets (data_source_id);
create index idx_data_assets_org_class on public.data_assets (organization_id, classification);
create index idx_data_assets_org_sensitivity on public.data_assets (organization_id, sensitivity_level);

create trigger data_assets_set_updated_at
  before update on public.data_assets
  for each row execute function public.set_updated_at();

-- Sensitive data findings ----------------------------------------------------
-- Never store actual secrets, passwords, API keys, or customer PII here.
-- metadata describes the finding (counts, field names, confidence), not content.
create table public.sensitive_data_findings (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  data_asset_id uuid not null references public.data_assets(id) on delete cascade,
  finding_type text not null
    check (finding_type in ('pii', 'financial', 'credential', 'source_code', 'healthcare', 'confidential', 'secret')),
  severity text not null default 'medium'
    check (severity in ('low', 'medium', 'high', 'critical')),
  description text not null,
  field_name text,
  detected_count integer not null default 0 check (detected_count >= 0),
  status text not null default 'open'
    check (status in ('open', 'resolved', 'ignored')),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index idx_findings_org on public.sensitive_data_findings (organization_id);
create index idx_findings_asset on public.sensitive_data_findings (data_asset_id);
create index idx_findings_org_status on public.sensitive_data_findings (organization_id, status);

create trigger sensitive_data_findings_set_updated_at
  before update on public.sensitive_data_findings
  for each row execute function public.set_updated_at();

-- =============================================================================
-- supabase/migrations/003_ai.sql
-- =============================================================================
-- 003_ai.sql
-- AI models/providers, AI agents, agent data permissions.

-- AI models ------------------------------------------------------------------
create table public.ai_models (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  provider text not null,
  model_identifier text not null,
  model_type text not null default 'chat'
    check (model_type in ('chat', 'completion', 'embedding', 'agent', 'custom')),
  is_approved boolean not null default false,
  is_external boolean not null default true,
  risk_level text not null default 'medium'
    check (risk_level in ('low', 'medium', 'high', 'critical')),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index idx_ai_models_org on public.ai_models (organization_id);

create trigger ai_models_set_updated_at
  before update on public.ai_models
  for each row execute function public.set_updated_at();

-- AI agents -------------------------------------------------------------------
create table public.ai_agents (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  description text,
  owner_user_id uuid,
  ai_model_id uuid references public.ai_models(id) on delete set null,
  status text not null default 'active'
    check (status in ('active', 'paused', 'disabled')),
  risk_level text not null default 'medium'
    check (risk_level in ('low', 'medium', 'high', 'critical')),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index idx_ai_agents_org on public.ai_agents (organization_id);
create index idx_ai_agents_org_status on public.ai_agents (organization_id, status);

create trigger ai_agents_set_updated_at
  before update on public.ai_agents
  for each row execute function public.set_updated_at();

-- Agent data permissions -------------------------------------------------------
-- One agent can hold different permissions across many sources/assets.
create table public.ai_agent_data_permissions (
  id uuid primary key default gen_random_uuid(),
  agent_id uuid not null references public.ai_agents(id) on delete cascade,
  data_source_id uuid references public.data_sources(id) on delete cascade,
  data_asset_id uuid references public.data_assets(id) on delete cascade,
  permission_type text not null
    check (permission_type in ('read', 'write', 'delete', 'share')),
  created_at timestamptz not null default now(),
  check (data_source_id is not null or data_asset_id is not null),
  unique (agent_id, data_source_id, data_asset_id, permission_type)
);

create index idx_agent_perms_agent on public.ai_agent_data_permissions (agent_id);
create index idx_agent_perms_source on public.ai_agent_data_permissions (data_source_id);
create index idx_agent_perms_asset on public.ai_agent_data_permissions (data_asset_id);

-- =============================================================================
-- supabase/migrations/004_policies.sql
-- =============================================================================
-- 004_policies.sql
-- Enforceable AI access policies. Rules are JSONB conditions so the
-- policy language can evolve without schema changes.
--
-- Example rule:
-- {
--   "conditions": [
--     { "field": "data.classification", "operator": "equals", "value": "pii" },
--     { "field": "ai.is_external", "operator": "equals", "value": true }
--   ]
-- }

create table public.policies (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  description text,
  status text not null default 'active'
    check (status in ('active', 'paused', 'archived')),
  priority integer not null default 100,
  rule jsonb not null default '{"conditions": []}'::jsonb,
  action text not null default 'review'
    check (action in ('allow', 'block', 'redact', 'review')),
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index idx_policies_org on public.policies (organization_id);
create index idx_policies_org_status_priority on public.policies (organization_id, status, priority);

create trigger policies_set_updated_at
  before update on public.policies
  for each row execute function public.set_updated_at();

-- =============================================================================
-- supabase/migrations/005_requests.sql
-- =============================================================================
-- 005_requests.sql
-- AI requests, per-request data access, and policy evaluations.
--
-- IMPORTANT: never store raw sensitive prompts or private customer data here.
-- metadata holds safe demo/operational context only.

create table public.ai_requests (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid,
  agent_id uuid references public.ai_agents(id) on delete set null,
  ai_model_id uuid references public.ai_models(id) on delete set null,
  purpose text not null,
  request_type text not null default 'chat'
    check (request_type in ('chat', 'completion', 'agent_action', 'data_access', 'tool_call')),
  status text not null default 'pending'
    check (status in ('pending', 'allowed', 'blocked', 'review', 'error')),
  risk_level text not null default 'low'
    check (risk_level in ('low', 'medium', 'high', 'critical')),
  source_ip inet,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index idx_ai_requests_org on public.ai_requests (organization_id);
create index idx_ai_requests_org_created on public.ai_requests (organization_id, created_at desc);
create index idx_ai_requests_org_status on public.ai_requests (organization_id, status);
create index idx_ai_requests_model on public.ai_requests (ai_model_id);
create index idx_ai_requests_agent on public.ai_requests (agent_id);

-- One request can touch many data assets --------------------------------------
create table public.ai_request_data (
  id uuid primary key default gen_random_uuid(),
  ai_request_id uuid not null references public.ai_requests(id) on delete cascade,
  data_asset_id uuid not null references public.data_assets(id) on delete cascade,
  access_type text not null default 'read'
    check (access_type in ('read', 'write', 'delete', 'share')),
  created_at timestamptz not null default now(),
  unique (ai_request_id, data_asset_id, access_type)
);

create index idx_ai_request_data_request on public.ai_request_data (ai_request_id);
create index idx_ai_request_data_asset on public.ai_request_data (data_asset_id);

-- Policy evaluations -----------------------------------------------------------
create table public.policy_evaluations (
  id uuid primary key default gen_random_uuid(),
  ai_request_id uuid not null references public.ai_requests(id) on delete cascade,
  policy_id uuid not null references public.policies(id) on delete cascade,
  decision text not null
    check (decision in ('allow', 'block', 'review')),
  reason text,
  checks jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index idx_policy_evals_request on public.policy_evaluations (ai_request_id);
create index idx_policy_evals_policy on public.policy_evaluations (policy_id);

-- =============================================================================
-- supabase/migrations/006_risk_audit.sql
-- =============================================================================
-- 006_risk_audit.sql
-- Risk events and append-only audit logs.

create table public.risk_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  ai_request_id uuid references public.ai_requests(id) on delete set null,
  data_asset_id uuid references public.data_assets(id) on delete set null,
  ai_agent_id uuid references public.ai_agents(id) on delete set null,
  title text not null,
  description text,
  severity text not null default 'medium'
    check (severity in ('low', 'medium', 'high', 'critical')),
  status text not null default 'open'
    check (status in ('open', 'investigating', 'resolved', 'ignored')),
  recommended_action text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index idx_risk_events_org on public.risk_events (organization_id);
create index idx_risk_events_org_status on public.risk_events (organization_id, status);
create index idx_risk_events_org_severity on public.risk_events (organization_id, severity);

create trigger risk_events_set_updated_at
  before update on public.risk_events
  for each row execute function public.set_updated_at();

-- Audit logs are append-only from the application's perspective:
-- RLS below grants SELECT and INSERT only, never UPDATE or DELETE.
create table public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  actor_user_id uuid,
  actor_type text not null default 'user'
    check (actor_type in ('user', 'ai_agent', 'system', 'admin')),
  action text not null,
  resource_type text,
  resource_id uuid,
  result text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index idx_audit_logs_org on public.audit_logs (organization_id);
create index idx_audit_logs_org_created on public.audit_logs (organization_id, created_at desc);
create index idx_audit_logs_org_action on public.audit_logs (organization_id, action);

-- =============================================================================
-- supabase/migrations/007_rls.sql
-- =============================================================================
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

-- =============================================================================
-- supabase/migrations/008_functions.sql
-- =============================================================================
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

-- =============================================================================
-- supabase/migrations/009_seed.sql
-- =============================================================================
-- 009_seed.sql
-- Fictional demo data for the Data Control Plane prototype.
-- No real people, secrets, or customer data. Safe to ship.

-- Organization ------------------------------------------------------------------
insert into public.organizations (id, name, slug, plan, status, settings)
values (
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  'Acme Technologies',
  'acme-technologies',
  'startup',
  'active',
  '{"demo": true}'::jsonb
)
on conflict (id) do nothing;

-- Demo members (fictional identities; real users sign up via Supabase Auth) ------
insert into public.organization_members (id, organization_id, user_id, role, status)
values
  ('b0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a1', 'owner', 'active'),
  ('b0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a2', 'security', 'active'),
  ('b0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a3', 'developer', 'active'),
  ('b0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a4', 'analyst', 'active'),
  ('b0000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a5', 'viewer', 'active')
on conflict (id) do nothing;
-- Sarah Chen (owner), Alex Kim (security), Mike Ross (developer),
-- Priya Shah (analyst), Daniel Wilson (viewer).

-- Data sources --------------------------------------------------------------------
insert into public.data_sources (id, organization_id, name, type, status, description, last_scan_at, metadata)
values
  ('c0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Google Drive', 'google_drive', 'demo', 'Company documents and shared drives.', now() - interval '12 minutes', '{"files": 184220}'::jsonb),
  ('c0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'GitHub', 'github', 'demo', 'Engineering repositories.', now() - interval '34 minutes', '{"repositories": 312}'::jsonb),
  ('c0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'PostgreSQL', 'postgresql', 'demo', 'Primary application database.', now() - interval '8 minutes', '{"schemas": 42}'::jsonb),
  ('c0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Slack', 'slack', 'demo', 'Team communication channels.', now() - interval '21 minutes', '{"channels": 96}'::jsonb),
  ('c0000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Notion', 'notion', 'demo', 'Internal wiki and docs.', now() - interval '47 minutes', '{"pages": 18402}'::jsonb),
  ('c0000000-0000-4000-8000-000000000006', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'AWS S3', 'aws_s3', 'demo', 'Object storage buckets.', now() - interval '1 hour', '{"buckets": 64}'::jsonb)
on conflict (id) do nothing;

-- Data assets -----------------------------------------------------------------------
insert into public.data_assets (id, organization_id, data_source_id, name, asset_type, classification, sensitivity_level, last_scanned_at, metadata)
values
  ('d0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000003', 'customers', 'table', 'restricted', 'high', now() - interval '8 minutes', '{"demo_note": "Customer Database"}'::jsonb),
  ('d0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000003', 'support_tickets', 'table', 'confidential', 'medium', now() - interval '8 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000001', 'product_docs', 'document', 'internal', 'low', now() - interval '12 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000002', 'engineering_repo', 'repository', 'confidential', 'medium', now() - interval '34 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000003', 'finance_ledger', 'table', 'restricted', 'critical', now() - interval '8 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000006', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000004', 'support_channel', 'channel', 'internal', 'low', now() - interval '21 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000007', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000006', 'design_assets', 'bucket', 'internal', 'none', now() - interval '1 hour', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000008', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000005', 'hr_records', 'record', 'restricted', 'high', now() - interval '47 minutes', '{}'::jsonb)
on conflict (id) do nothing;

-- Sensitive findings (descriptions only — never real secrets) --------------------------
insert into public.sensitive_data_findings (id, organization_id, data_asset_id, finding_type, severity, description, field_name, detected_count, status, metadata)
values
  ('e0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'd0000000-0000-4000-8000-000000000001', 'pii', 'high', 'Customer identifiers and contact fields detected in customers table.', 'email_address', 128400, 'open', '{"confidence": 0.98}'::jsonb),
  ('e0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'd0000000-0000-4000-8000-000000000005', 'financial', 'critical', 'Ledger balances and account references detected.', 'balance_cents', 48210, 'open', '{"confidence": 0.99}'::jsonb),
  ('e0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'd0000000-0000-4000-8000-000000000004', 'credential', 'high', 'Patterns resembling tokens found in CI configuration files.', 'ci_config', 12, 'open', '{"confidence": 0.87}'::jsonb),
  ('e0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'd0000000-0000-4000-8000-000000000008', 'confidential', 'medium', 'Employment records flagged as restricted.', null, 640, 'open', '{"confidence": 0.91}'::jsonb)
on conflict (id) do nothing;

-- AI models ------------------------------------------------------------------------------
insert into public.ai_models (id, organization_id, name, provider, model_identifier, model_type, is_approved, is_external, risk_level, metadata)
values
  ('f0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'GPT', 'OpenAI', 'gpt-example', 'chat', true, true, 'medium', '{}'::jsonb),
  ('f0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Claude', 'Anthropic', 'claude-example', 'chat', true, true, 'medium', '{}'::jsonb),
  ('f0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Gemini', 'Google', 'gemini-example', 'chat', false, true, 'high', '{}'::jsonb),
  ('f0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Llama', 'Meta', 'llama-example', 'chat', true, true, 'low', '{}'::jsonb),
  ('f0000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Internal AI', 'Acme', 'internal-1', 'agent', true, false, 'low', '{}'::jsonb)
on conflict (id) do nothing;

-- AI agents ----------------------------------------------------------------------------------
insert into public.ai_agents (id, organization_id, name, description, ai_model_id, status, risk_level, metadata)
values
  ('10000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Customer Support Agent', 'Answers customer questions from CRM and docs.', 'f0000000-0000-4000-8000-000000000002', 'active', 'low', '{"owner": "Support Ops"}'::jsonb),
  ('10000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Internal Research Agent', 'Summarizes internal research material.', 'f0000000-0000-4000-8000-000000000005', 'active', 'medium', '{"owner": "Data Science"}'::jsonb),
  ('10000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Code Agent', 'Assists with code review and CI triage.', 'f0000000-0000-4000-8000-000000000001', 'paused', 'medium', '{"owner": "Engineering"}'::jsonb),
  ('10000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Finance Assistant', 'Drafts finance summaries for the finance team.', 'f0000000-0000-4000-8000-000000000005', 'active', 'high', '{"owner": "Finance"}'::jsonb)
on conflict (id) do nothing;

insert into public.ai_agent_data_permissions (agent_id, data_source_id, data_asset_id, permission_type)
values
  ('10000000-0000-4000-8000-000000000001', null, 'd0000000-0000-4000-8000-000000000001', 'read'),
  ('10000000-0000-4000-8000-000000000001', null, 'd0000000-0000-4000-8000-000000000002', 'read'),
  ('10000000-0000-4000-8000-000000000001', null, 'd0000000-0000-4000-8000-000000000003', 'read'),
  ('10000000-0000-4000-8000-000000000002', null, 'd0000000-0000-4000-8000-000000000003', 'read'),
  ('10000000-0000-4000-8000-000000000003', null, 'd0000000-0000-4000-8000-000000000004', 'read'),
  ('10000000-0000-4000-8000-000000000004', null, 'd0000000-0000-4000-8000-000000000005', 'read')
on conflict do nothing;

-- Policies ---------------------------------------------------------------------------------------
insert into public.policies (id, organization_id, name, description, status, priority, rule, action, created_by)
values
  ('20000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Customer PII Protection', 'Customer PII cannot be sent to external AI.', 'active', 10,
   '{"conditions": [{"field": "data.classification", "operator": "in", "value": ["restricted", "confidential"]}, {"field": "ai.is_external", "operator": "equals", "value": true}]}'::jsonb,
   'block', null),
  ('20000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Internal AI Access', 'Approved internal agents may access internal data.', 'active', 50,
   '{"conditions": [{"field": "ai.is_approved", "operator": "equals", "value": true}, {"field": "ai.is_external", "operator": "equals", "value": false}]}'::jsonb,
   'allow', null),
  ('20000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Financial Data Protection', 'Critical financial data cannot leave the finance boundary.', 'active', 20,
   '{"conditions": [{"field": "data.sensitivity_level", "operator": "equals", "value": "critical"}]}'::jsonb,
   'block', null)
on conflict (id) do nothing;

-- Demo AI requests (ALLOWED and BLOCKED) --------------------------------------------------------------
insert into public.ai_requests (id, organization_id, user_id, agent_id, ai_model_id, purpose, request_type, status, risk_level, metadata, created_at)
values
  ('30000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a2', null, 'f0000000-0000-4000-8000-000000000002', 'Customer Analysis', 'chat', 'blocked', 'high',
   '{"user_name": "Alex Kim", "demo": true}'::jsonb, now() - interval '2 hours'),
  ('30000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a1', '10000000-0000-4000-8000-000000000001', 'f0000000-0000-4000-8000-000000000005', 'Customer Support', 'agent_action', 'allowed', 'low',
   '{"user_name": "Sarah Chen", "demo": true}'::jsonb, now() - interval '5 hours'),
  ('30000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a3', null, 'f0000000-0000-4000-8000-000000000001', 'Code Review', 'completion', 'allowed', 'medium',
   '{"user_name": "Mike Ross", "demo": true}'::jsonb, now() - interval '1 day'),
  ('30000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a4', null, 'f0000000-0000-4000-8000-000000000003', 'Market Research', 'chat', 'review', 'high',
   '{"user_name": "Priya Shah", "demo": true}'::jsonb, now() - interval '2 days'),
  ('30000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', null, '10000000-0000-4000-8000-000000000004', 'f0000000-0000-4000-8000-000000000005', 'Finance Summary', 'agent_action', 'allowed', 'medium',
   '{"user_name": "Finance Assistant", "demo": true}'::jsonb, now() - interval '3 days'),
  ('30000000-0000-4000-8000-000000000006', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a2', null, 'f0000000-0000-4000-8000-000000000002', 'Customer Analysis', 'chat', 'blocked', 'high',
   '{"user_name": "Alex Kim", "demo": true}'::jsonb, now() - interval '4 days')
on conflict (id) do nothing;

insert into public.ai_request_data (ai_request_id, data_asset_id, access_type)
values
  ('30000000-0000-4000-8000-000000000001', 'd0000000-0000-4000-8000-000000000001', 'read'),
  ('30000000-0000-4000-8000-000000000002', 'd0000000-0000-4000-8000-000000000003', 'read'),
  ('30000000-0000-4000-8000-000000000003', 'd0000000-0000-4000-8000-000000000004', 'read'),
  ('30000000-0000-4000-8000-000000000004', 'd0000000-0000-4000-8000-000000000001', 'read'),
  ('30000000-0000-4000-8000-000000000005', 'd0000000-0000-4000-8000-000000000005', 'read'),
  ('30000000-0000-4000-8000-000000000006', 'd0000000-0000-4000-8000-000000000001', 'read')
on conflict do nothing;

insert into public.policy_evaluations (ai_request_id, policy_id, decision, reason, checks)
values
  ('30000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'block', 'Customer PII cannot be sent to external AI.',
   '{"identity": true, "permission": true, "data_classification": false, "ai_destination": false, "purpose": true}'::jsonb),
  ('30000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000002', 'allow', 'Approved internal agents may access internal data.',
   '{"identity": true, "permission": true, "data_classification": true, "ai_destination": true, "purpose": true}'::jsonb),
  ('30000000-0000-4000-8000-000000000006', '20000000-0000-4000-8000-000000000001', 'block', 'Customer PII cannot be sent to external AI.',
   '{"identity": true, "permission": true, "data_classification": false, "ai_destination": false, "purpose": true}'::jsonb)
on conflict do nothing;

insert into public.risk_events (organization_id, ai_request_id, title, description, severity, status, recommended_action, metadata)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '30000000-0000-4000-8000-000000000001', 'AI request blocked (high risk)', 'Customer PII cannot be sent to external AI.', 'high', 'open',
   'Review the triggered policies before retrying.', '{"demo": true}'::jsonb),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '30000000-0000-4000-8000-000000000004', 'AI request review (high risk)', 'Unapproved external model used with restricted data.', 'high', 'investigating',
   'Manually review this request in the audit log.', '{"demo": true}'::jsonb)
on conflict do nothing;

insert into public.audit_logs (organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a2', 'user', 'ai_request_blocked', 'ai_request', '30000000-0000-4000-8000-000000000001', 'blocked', '{"demo": true}'::jsonb),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a1', 'ai_agent', 'ai_request_allowed', 'ai_request', '30000000-0000-4000-8000-000000000002', 'allowed', '{"demo": true}'::jsonb),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', null, 'system', 'data_asset_scanned', 'data_source', 'c0000000-0000-4000-8000-000000000003', 'success', '{"demo": true}'::jsonb)
on conflict do nothing;


-- =============================================================================
-- supabase/migrations/010_hardening.sql
-- =============================================================================
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
