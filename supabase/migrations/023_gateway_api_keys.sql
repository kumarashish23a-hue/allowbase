-- 023_gateway_api_keys.sql
-- Machine-to-machine authentication for the AI gateway.
--
-- Until now API keys only carried the 'ingest' scope (ingest-event). This
-- migration:
--   1. Widens create_api_key to accept the 'gateway' scope, so owner/admins
--      can mint keys that may call the ai-gateway edge function directly.
--   2. Adds public.verify_api_key(p_key_hash, p_scope): a SECURITY DEFINER
--      RPC (service_role only) that authenticates a key hash for one scope.
--      It rejects revoked keys, expired keys, and keys lacking the scope,
--      touches last_used_at, and returns {key_id, organization_id}.
--      Failures raise 'invalid api key' (errcode 28000), mirroring
--      ingest_api_event, so edge functions can map it to HTTP 401 without
--      leaking which check failed.
--
-- Security properties (unchanged from 011):
--   - Only the SHA-256 hash is stored; the plaintext is returned once.
--   - A gateway key authenticates the *organization*: callers cannot pick an
--     organization_id — the edge function takes it from the key.

-- 1. Allow the 'gateway' scope when minting keys. Body is 011 verbatim
--    except the scope whitelist.
create or replace function public.create_api_key(
  p_organization_id uuid,
  p_name text,
  p_scopes text[] default array['ingest']::text[],
  p_expires_at timestamptz default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_key text;
  v_hash text;
  v_prefix text;
  v_id uuid;
  v_scopes text[] := coalesce(p_scopes, array['ingest']::text[]);
begin
  if not public.has_org_role(p_organization_id, array['owner', 'admin']) then
    raise exception 'creating API keys requires the owner or admin role' using errcode = '42501';
  end if;
  if p_name is null or char_length(p_name) = 0 or char_length(p_name) > 100 then
    raise exception 'key name must be 1-100 characters';
  end if;
  if not (v_scopes <@ array['ingest', 'gateway']::text[]) or array_length(v_scopes, 1) is null then
    raise exception 'unknown scope requested';
  end if;
  if p_expires_at is not null and p_expires_at <= now() then
    raise exception 'expiry must be in the future';
  end if;

  -- dcp_live_<64 hex chars> from 32 cryptographic random bytes.
  v_key := 'dcp_live_' || encode(gen_random_bytes(32), 'hex');
  v_hash := encode(digest(v_key, 'sha256'), 'hex');
  v_prefix := left(v_key, 12);

  insert into public.api_keys (organization_id, name, key_hash, key_prefix, scopes, expires_at, created_by)
  values (p_organization_id, p_name, v_hash, v_prefix, v_scopes, p_expires_at, auth.uid())
  returning id into v_id;

  return jsonb_build_object('id', v_id, 'key', v_key, 'prefix', v_prefix);
end;
$$;

grant execute on function public.create_api_key(uuid, text, text[], timestamptz) to authenticated;

-- 2. Authenticate a key hash for a single scope. Service-role only: only our
--    own edge functions call this.
create or replace function public.verify_api_key(p_key_hash text, p_scope text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row public.api_keys%rowtype;
begin
  select * into v_row from public.api_keys where key_hash = p_key_hash;
  if not found
     or v_row.revoked_at is not null
     or (v_row.expires_at is not null and v_row.expires_at <= now())
     or not (v_row.scopes @> array[p_scope]::text[]) then
    -- Deliberately vague: never reveal which check failed.
    raise exception 'invalid api key' using errcode = '28000';
  end if;

  update public.api_keys set last_used_at = now() where id = v_row.id;

  return jsonb_build_object(
    'key_id', v_row.id,
    'organization_id', v_row.organization_id
  );
end;
$$;

grant execute on function public.verify_api_key(text, text) to service_role;
