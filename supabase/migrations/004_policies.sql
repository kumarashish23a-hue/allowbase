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
