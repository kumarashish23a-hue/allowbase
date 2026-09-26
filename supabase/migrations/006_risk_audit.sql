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
