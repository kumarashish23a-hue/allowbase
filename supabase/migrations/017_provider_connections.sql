-- 017_provider_connections.sql
--
-- Server-side AI provider credentials for the AI gateway.
--
-- API keys are encrypted by the edge function (AES-GCM via WebCrypto, key
-- from the PROVIDER_ENCRYPTION_KEY Supabase secret) BEFORE they reach
-- Postgres. The database never sees plaintext keys and the API never
-- returns them: only key_hint (last 4 characters) is exposed for display.
--
-- RLS is enabled with intentionally NO policies for authenticated roles, so
-- direct table access is denied for everyone. Every read and write goes
-- through the ai-provider / ai-gateway edge functions, which use the service
-- role and enforce organization membership + role from the caller's JWT.

create table public.ai_provider_connections (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  provider text not null check (provider in ('openai', 'anthropic', 'gemini', 'custom')),
  label text not null,
  base_url text,
  key_ciphertext text not null,
  key_iv text not null,
  key_hint text not null,
  status text not null default 'active' check (status in ('active', 'revoked')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, provider)
);

alter table public.ai_provider_connections enable row level security;

create index idx_provider_connections_org on public.ai_provider_connections (organization_id);

comment on table public.ai_provider_connections is
  'Encrypted AI provider API keys. Plaintext never reaches Postgres; only key_hint is ever returned to clients.';
comment on column public.ai_provider_connections.key_ciphertext is
  'AES-GCM ciphertext (base64). Decryptable only by the edge function holding PROVIDER_ENCRYPTION_KEY.';
