-- 024_gateway_evaluate_wrapper.sql
--
-- Two fixes from the machine-auth review:
--
-- 1. evaluate_gateway_request: a service-role-only RPC for the ai-gateway
--    edge function. It authenticates an organization-bound API key for the
--    'gateway' scope, stamps the transaction-local app.api_key_id trust
--    marker (the same pattern ingest_api_event uses at 011), and then runs
--    the one real evaluator. Without the stamp, evaluate_ai_request would
--    see no auth.uid() (service_role has none) and raise 42501 — so the
--    gateway must never call evaluate_ai_request directly as service_role.
--    Key failures raise 'invalid api key' (errcode 28000), mirroring the
--    other machine entry points.
--
-- 2. check_rate_limit was granted to anon in 020. It is only ever called by
--    our own edge functions through the service_role client, so it is now
--    revoked from anon and authenticated. (Anyone could previously bump
--    arbitrary rate-limit buckets.)

create or replace function public.evaluate_gateway_request(
  p_key_hash text,
  p_organization_id uuid,
  p_ai_model_id uuid,
  p_purpose text,
  p_data_asset_ids uuid[],
  p_agent_id uuid default null,
  p_request_type text default 'chat',
  p_content_findings jsonb default '[]'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key_id uuid;
begin
  -- Authenticate the key for the gateway scope, bound to this organization.
  -- Deliberately vague on failure: never reveal which check failed.
  select id into v_key_id
  from public.api_keys
  where key_hash = p_key_hash
    and organization_id = p_organization_id
    and revoked_at is null
    and (expires_at is null or expires_at > now())
    and scopes @> array['gateway']::text[];
  if not found then
    raise exception 'invalid api key' using errcode = '28000';
  end if;

  update public.api_keys set last_used_at = now() where id = v_key_id;

  -- Stamp the trusted machine context, then run the one real evaluator.
  -- Transaction-local: it vanishes when this call's transaction ends.
  perform set_config('app.api_key_id', v_key_id::text, true);

  return public.evaluate_ai_request(
    p_organization_id,
    p_ai_model_id,
    p_purpose,
    coalesce(p_data_asset_ids, '{}'::uuid[]),
    null,
    p_agent_id,
    coalesce(p_request_type, 'chat'),
    coalesce(p_content_findings, '[]'::jsonb)
  );
end;
$$;

grant execute on function public.evaluate_gateway_request(text, uuid, uuid, text, uuid[], uuid, text, jsonb)
  to service_role;

-- The limiter is only called server-side via the service_role client.
-- Note: Postgres grants EXECUTE on new functions to PUBLIC by default, and
-- every role (including anon) is implicitly a member of PUBLIC — so the
-- explicit grant to anon/authenticated in 020 was not even the whole story.
-- Revoke from PUBLIC as well, or anyone could bump arbitrary buckets.
revoke execute on function public.check_rate_limit(text, integer, integer) from anon, authenticated, public;

-- Same hardening for the new wrapper: only our own edge functions (which
-- hold the service key) may invoke it. The key hash inside remains the
-- actual credential, but there is no reason to let anon reach the RPC at all.
revoke execute on function public.evaluate_gateway_request(text, uuid, uuid, text, uuid[], uuid, text, jsonb)
  from public;
