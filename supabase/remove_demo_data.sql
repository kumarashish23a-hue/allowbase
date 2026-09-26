-- Data Control Plane: remove starter-kit demo data
--
-- Run this in Supabase Dashboard > SQL Editor > New query, then click Run.
--
-- Deletes ONLY the rows created by supabase/starter_kit.sql:
--   * the 2 demo data sources (status = 'demo')
--   * their 2 demo data assets (+ the demo sensitive-data finding, via cascade)
--   * the starter agent's data grant (via cascade)
--   * the starter AI agent and the 2 demo AI models
--   * the 3 demo policies
--   * simulator requests tied to those demo rows (+ their evaluations and
--     approval requests, via cascade) and demo risk events
--
-- NOT touched:
--   * your real database connections (status = 'connected') and any
--     discovered catalog under them
--   * anything you created yourself (policies, agents, models)
--   * the Acme Technologies demo org from the migrations (explicitly excluded)
--   * audit_logs — append-only by design, kept as your compliance history
--
-- Safe to re-run: every delete only matches starter-kit markers, so running
-- it twice deletes nothing the second time.

-- 0. Never touch the Acme demo org shipped with the migrations.
--    (Its rows share some names with the starter kit, so we exclude it by id.)

-- 1. Identify the starter-kit rows by the exact markers starter_kit.sql used.
drop table if exists demo_sources;
create temp table demo_sources as
select id, organization_id
from public.data_sources
where organization_id <> 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  and status = 'demo'
  and name in ('PostgreSQL', 'Google Drive');

drop table if exists demo_assets;
create temp table demo_assets as
select a.id, a.organization_id
from public.data_assets a
join demo_sources s on s.id = a.data_source_id
where a.organization_id <> 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  and a.name in ('Customer Database', 'Product Documentation');

drop table if exists demo_models;
create temp table demo_models as
select id, organization_id
from public.ai_models
where organization_id <> 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  and name in ('Claude', 'Internal Support Agent');

drop table if exists demo_agents;
create temp table demo_agents as
select id, organization_id
from public.ai_agents
where organization_id <> 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  and name = 'Customer Support Agent';

drop table if exists demo_policies;
create temp table demo_policies as
select id, organization_id
from public.policies
where organization_id <> 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  and name in ('Customer PII Protection', 'Internal AI Access', 'External Docs Need Approval');

-- 2. Simulator requests tied to the demo rows.
--    (Cascades to ai_request_data, policy_evaluations, and approval_requests.)
delete from public.ai_requests r
where r.agent_id in (select id from demo_agents)
   or r.ai_model_id in (select id from demo_models)
   or exists (
     select 1 from public.ai_request_data d
     where d.ai_request_id = r.id
       and d.data_asset_id in (select id from demo_assets)
   )
   or exists (
     select 1 from public.policy_evaluations e
     where e.ai_request_id = r.id
       and e.policy_id in (select id from demo_policies)
   );

-- 3. Demo risk events from the affected organizations.
delete from public.risk_events
where organization_id in (select organization_id from demo_sources);

-- 4. Demo assets.
--    (Cascades to sensitive_data_findings, ai_agent_data_permissions,
--     ai_request_data, and any remaining policy_evaluations.)
delete from public.data_assets a
using demo_assets d
where a.id = d.id;

-- 5. Demo sources.
delete from public.data_sources s
using demo_sources d
where s.id = d.id;

-- 6. Demo agents, models, and policies.
delete from public.ai_agents a
using demo_agents d
where a.id = d.id;

delete from public.ai_models m
using demo_models d
where m.id = d.id;

delete from public.policies p
using demo_policies d
where p.id = d.id;

-- 7. Show what each organization holds now.
select o.name as organization,
  (select count(*) from public.data_sources s where s.organization_id = o.id) as data_sources,
  (select count(*) from public.data_assets a where a.organization_id = o.id) as data_assets,
  (select count(*) from public.ai_models m where m.organization_id = o.id) as ai_models,
  (select count(*) from public.ai_agents a where a.organization_id = o.id) as ai_agents,
  (select count(*) from public.policies p where p.organization_id = o.id) as policies,
  (select count(*) from public.ai_requests r where r.organization_id = o.id) as ai_requests
from public.organizations o
order by o.created_at;
