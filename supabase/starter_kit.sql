-- Data Control Plane: starter kit for real organizations
--
-- Run this in Supabase Dashboard > SQL Editor > New query, then click Run.
-- Safe to re-run: every section only touches organizations that have
-- zero rows in that table, so existing data (including the Acme demo org)
-- is never duplicated or modified.
--
-- What it creates per empty organization:
--   2 data sources, 2 data assets, 2 AI models, 1 agent, 3 policies,
--   1 agent data grant, 1 sensitive-data finding.
-- The names match the request simulator presets, so after running this
-- (and deploying the evaluate-ai-request Edge Function) the simulator
-- performs REAL policy evaluations stored in your database.
--
-- Try these in the simulator after loading:
--   Claude + Customer Database                    -> BLOCK (PII policy)
--   Internal Support Agent + Product Documentation -> ALLOW
--   Claude + Product Documentation                -> PENDING APPROVAL
--   Claude + Customer Database as Customer Support Agent -> BLOCK (no grant)

-- 1. Data sources ------------------------------------------------------------
insert into public.data_sources (id, organization_id, name, type, status, description, last_scan_at, metadata)
select gen_random_uuid(), o.id, s.name, s.type, 'demo', s.description, now(), '{}'::jsonb
from public.organizations o
cross join (values
  ('PostgreSQL', 'postgresql', 'Primary application database.'),
  ('Google Drive', 'google_drive', 'Company documents and shared drives.')
) as s(name, type, description)
where not exists (select 1 from public.data_sources d where d.organization_id = o.id);

-- 2. Data assets --------------------------------------------------------------
insert into public.data_assets (id, organization_id, data_source_id, name, asset_type, classification, sensitivity_level, last_scanned_at, metadata)
select gen_random_uuid(), o.id,
  (select d.id from public.data_sources d where d.organization_id = o.id and d.type = a.source_type limit 1),
  a.name, a.asset_type, a.classification, a.sensitivity, now(), a.metadata
from public.organizations o
cross join (values
  ('Customer Database', 'table', 'restricted', 'high', 'postgresql', '{"demo_note": "Customer Database"}'::jsonb),
  ('Product Documentation', 'document', 'internal', 'low', 'google_drive', '{}'::jsonb)
) as a(name, asset_type, classification, sensitivity, source_type, metadata)
where not exists (select 1 from public.data_assets x where x.organization_id = o.id);

-- 3. AI models ----------------------------------------------------------------
insert into public.ai_models (id, organization_id, name, provider, model_identifier, model_type, is_approved, is_external, risk_level, metadata)
select gen_random_uuid(), o.id, m.name, m.provider, m.identifier, 'chat', m.approved, m.external, m.risk, '{}'::jsonb
from public.organizations o
cross join (values
  ('Claude', 'Anthropic', 'claude-4', true, true, 'medium'),
  ('Internal Support Agent', 'Internal', 'internal-support-1', true, false, 'low')
) as m(name, provider, identifier, approved, external, risk)
where not exists (select 1 from public.ai_models x where x.organization_id = o.id);

-- 4. AI agents -----------------------------------------------------------------
insert into public.ai_agents (id, organization_id, name, description, ai_model_id, status, risk_level, metadata)
select gen_random_uuid(), o.id,
  'Customer Support Agent',
  'Answers customer questions from docs and tickets.',
  (select m.id from public.ai_models m where m.organization_id = o.id and m.name = 'Internal Support Agent' limit 1),
  'active', 'low', '{"owner": "Support"}'::jsonb
from public.organizations o
where not exists (select 1 from public.ai_agents a where a.organization_id = o.id);

-- 4b. Starter agent data permission ------------------------------------------------
-- The starter agent may read Product Documentation and nothing else.
-- Requests attributed to it without a grant are denied by default.
insert into public.ai_agent_data_permissions (id, agent_id, data_source_id, data_asset_id, permission_type)
select gen_random_uuid(), a.id, null, d.id, 'read'
from public.organizations o
join public.ai_agents a on a.organization_id = o.id and a.name = 'Customer Support Agent'
join public.data_assets d on d.organization_id = o.id and d.name = 'Product Documentation'
where not exists (
  select 1 from public.ai_agent_data_permissions p
  where p.agent_id = a.id and p.data_asset_id = d.id and p.permission_type = 'read'
);

-- 5. Policies -------------------------------------------------------------------
insert into public.policies (id, organization_id, name, description, status, priority, rule, action, created_by)
select gen_random_uuid(), o.id, p.name, p.description, 'active', p.priority, p.rule::jsonb, p.action, null
from public.organizations o
cross join (values
  ('Customer PII Protection',
   'Restricted customer data cannot be sent to external AI.',
   10,
   '{"conditions": [{"field": "data.classification", "operator": "in", "value": ["restricted", "confidential"]}, {"field": "ai.is_external", "operator": "equals", "value": true}]}',
   'block'),
  ('Internal AI Access',
   'Approved internal models may access internal data.',
   50,
   '{"conditions": [{"field": "ai.is_approved", "operator": "equals", "value": true}, {"field": "ai.is_external", "operator": "equals", "value": false}]}',
   'allow'),
  ('External Docs Need Approval',
   'External AI reading internal documents needs a human approval.',
   20,
   '{"conditions": [{"field": "ai.is_external", "operator": "equals", "value": true}, {"field": "data.classification", "operator": "equals", "value": "internal"}]}',
   'require_approval')
) as p(name, description, priority, rule, action)
where not exists (select 1 from public.policies x where x.organization_id = o.id);

-- 6. Sensitive-data finding -------------------------------------------------------
insert into public.sensitive_data_findings (id, organization_id, data_asset_id, finding_type, severity, description, field_name, detected_count, status, metadata)
select gen_random_uuid(), o.id,
  (select a.id from public.data_assets a where a.organization_id = o.id and a.name = 'Customer Database' limit 1),
  'pii', 'high', 'Customer identifiers and contact fields detected.', 'email_address', 128400, 'open', '{"confidence": 0.98}'::jsonb
from public.organizations o
where not exists (select 1 from public.sensitive_data_findings f where f.organization_id = o.id);

-- Summary: what each organization now holds ---------------------------------------
select o.name as organization,
  (select count(*) from public.data_sources s where s.organization_id = o.id) as data_sources,
  (select count(*) from public.data_assets a where a.organization_id = o.id) as data_assets,
  (select count(*) from public.ai_models m where m.organization_id = o.id) as ai_models,
  (select count(*) from public.ai_agents a where a.organization_id = o.id) as ai_agents,
  (select count(*) from public.policies p where p.organization_id = o.id) as policies
from public.organizations o
order by o.created_at;
