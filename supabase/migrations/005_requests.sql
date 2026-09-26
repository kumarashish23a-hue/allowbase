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
