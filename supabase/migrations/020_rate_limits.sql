-- 020_rate_limits.sql
--
-- Fixed-window rate limiting for the edge functions.
--
-- Two tables:
--   rate_limit_counters — one row per bucket ("rl:<endpoint>:<scope>"),
--     tracking the current window start and hit count. RLS enabled with NO
--     permissive policies (deny-by-default): rows are written only through
--     the check_rate_limit SECURITY DEFINER function below. service_role
--     bypasses RLS; no one else reads or writes this table.
--   rate_limit_rules — per-endpoint max_requests / window_seconds tuned by
--     admins. Same deny-by-default RLS; read inside the shared Deno helper
--     only as a best-effort lookup (falls back to constants on RLS denial).
--
-- The Deno helper supabase/functions/_shared/rateLimit.ts depends on the
-- check_rate_limit contract below — do not change one without the other.

-- 1. rate_limit_counters ----------------------------------------------------
create table if not exists public.rate_limit_counters (
  bucket_key  text        primary key,
  window_start timestamptz not null,
  count       integer     not null default 1
);

alter table public.rate_limit_counters enable row level security;

-- Deliberately no policies: deny-by-default. The RPC writes as definer.

-- 2. rate_limit_rules --------------------------------------------------------
create table if not exists public.rate_limit_rules (
  endpoint       text    primary key,
  max_requests   integer not null,
  window_seconds integer not null
);

alter table public.rate_limit_rules enable row level security;

-- Deliberately no policies: deny-by-default. The helper reads best-effort
-- and falls back to its constants when RLS denies the read.

insert into public.rate_limit_rules (endpoint, max_requests, window_seconds)
values
  ('ingest-event',        600, 60),
  ('evaluate-ai-request', 300, 60),
  ('ai-gateway',          120, 60)
on conflict (endpoint) do nothing;

-- 3. check_rate_limit --------------------------------------------------------
-- Atomic fixed-window counter. Single INSERT ... ON CONFLICT statement:
-- if the stored window has expired, the window restarts (count back to 1);
-- otherwise the count increments. Returns {"allowed", "retry_after_seconds",
-- "limit", "count"} as jsonb.
drop function if exists public.check_rate_limit(text, integer, integer);

create or replace function public.check_rate_limit(
  p_bucket text,
  p_max integer,
  p_window_seconds integer
)
returns jsonb
language sql
security definer
set search_path = public
as $$
  with upsert as (
    insert into public.rate_limit_counters (bucket_key, window_start, count)
    values (p_bucket, now(), 1)
    on conflict (bucket_key) do update set
      window_start = case
        when public.rate_limit_counters.window_start <= now() - make_interval(secs => p_window_seconds)
        then now()
        else public.rate_limit_counters.window_start
      end,
      count = case
        when public.rate_limit_counters.window_start <= now() - make_interval(secs => p_window_seconds)
        then 1
        else public.rate_limit_counters.count + 1
      end
    returning public.rate_limit_counters.count,
              public.rate_limit_counters.window_start
  )
  select jsonb_build_object(
    'allowed',
      u.count <= p_max,
    'retry_after_seconds',
      case
        when u.count <= p_max then 0
        else greatest(
          0,
          ceil(extract(epoch from (u.window_start + make_interval(secs => p_window_seconds) - now())))::int
        )
      end,
    'limit', p_max,
    'count', u.count
  )
  from upsert u;
$$;

grant execute on function public.check_rate_limit(text, integer, integer)
  to anon, authenticated, service_role;
