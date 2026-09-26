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
