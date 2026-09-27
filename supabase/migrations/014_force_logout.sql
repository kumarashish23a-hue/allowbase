-- 014_force_logout.sql
--
-- Remote sign-out for workspace members. When an owner/admin force-logs-out
-- a member, the app sets force_logout_at; the member's app watches this flag
-- and signs them out (checked on load, every minute, and on window focus).
--
-- This is app-level enforcement: it signs the member out of the Data Control
-- Plane app promptly, but their API access token stays valid until it expires
-- (Supabase default: 1 hour). For immediate hard revocation, remove the
-- member or rotate API keys as well.
--
-- Run once in the Supabase SQL editor (project xusjrmruvzfwyaxtxylw).

alter table public.organization_members
  add column if not exists force_logout_at timestamptz;

comment on column public.organization_members.force_logout_at =
  'Set by an owner/admin to remotely sign this member out of the app.';
