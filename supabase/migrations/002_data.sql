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
