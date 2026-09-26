-- 009_seed.sql
-- Fictional demo data for the Data Control Plane prototype.
-- No real people, secrets, or customer data. Safe to ship.

-- Organization ------------------------------------------------------------------
insert into public.organizations (id, name, slug, plan, status, settings)
values (
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  'Acme Technologies',
  'acme-technologies',
  'startup',
  'active',
  '{"demo": true}'::jsonb
)
on conflict (id) do nothing;

-- Demo members (fictional identities; real users sign up via Supabase Auth) ------
insert into public.organization_members (id, organization_id, user_id, role, status)
values
  ('b0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a1', 'owner', 'active'),
  ('b0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a2', 'security', 'active'),
  ('b0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a3', 'developer', 'active'),
  ('b0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a4', 'analyst', 'active'),
  ('b0000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a5', 'viewer', 'active')
on conflict (id) do nothing;
-- Sarah Chen (owner), Alex Kim (security), Mike Ross (developer),
-- Priya Shah (analyst), Daniel Wilson (viewer).

-- Data sources --------------------------------------------------------------------
insert into public.data_sources (id, organization_id, name, type, status, description, last_scan_at, metadata)
values
  ('c0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Google Drive', 'google_drive', 'demo', 'Company documents and shared drives.', now() - interval '12 minutes', '{"files": 184220}'::jsonb),
  ('c0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'GitHub', 'github', 'demo', 'Engineering repositories.', now() - interval '34 minutes', '{"repositories": 312}'::jsonb),
  ('c0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'PostgreSQL', 'postgresql', 'demo', 'Primary application database.', now() - interval '8 minutes', '{"schemas": 42}'::jsonb),
  ('c0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Slack', 'slack', 'demo', 'Team communication channels.', now() - interval '21 minutes', '{"channels": 96}'::jsonb),
  ('c0000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Notion', 'notion', 'demo', 'Internal wiki and docs.', now() - interval '47 minutes', '{"pages": 18402}'::jsonb),
  ('c0000000-0000-4000-8000-000000000006', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'AWS S3', 'aws_s3', 'demo', 'Object storage buckets.', now() - interval '1 hour', '{"buckets": 64}'::jsonb)
on conflict (id) do nothing;

-- Data assets -----------------------------------------------------------------------
insert into public.data_assets (id, organization_id, data_source_id, name, asset_type, classification, sensitivity_level, last_scanned_at, metadata)
values
  ('d0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000003', 'customers', 'table', 'restricted', 'high', now() - interval '8 minutes', '{"demo_note": "Customer Database"}'::jsonb),
  ('d0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000003', 'support_tickets', 'table', 'confidential', 'medium', now() - interval '8 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000001', 'product_docs', 'document', 'internal', 'low', now() - interval '12 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000002', 'engineering_repo', 'repository', 'confidential', 'medium', now() - interval '34 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000003', 'finance_ledger', 'table', 'restricted', 'critical', now() - interval '8 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000006', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000004', 'support_channel', 'channel', 'internal', 'low', now() - interval '21 minutes', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000007', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000006', 'design_assets', 'bucket', 'internal', 'none', now() - interval '1 hour', '{}'::jsonb),
  ('d0000000-0000-4000-8000-000000000008', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'c0000000-0000-4000-8000-000000000005', 'hr_records', 'record', 'restricted', 'high', now() - interval '47 minutes', '{}'::jsonb)
on conflict (id) do nothing;

-- Sensitive findings (descriptions only — never real secrets) --------------------------
insert into public.sensitive_data_findings (id, organization_id, data_asset_id, finding_type, severity, description, field_name, detected_count, status, metadata)
values
  ('e0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'd0000000-0000-4000-8000-000000000001', 'pii', 'high', 'Customer identifiers and contact fields detected in customers table.', 'email_address', 128400, 'open', '{"confidence": 0.98}'::jsonb),
  ('e0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'd0000000-0000-4000-8000-000000000005', 'financial', 'critical', 'Ledger balances and account references detected.', 'balance_cents', 48210, 'open', '{"confidence": 0.99}'::jsonb),
  ('e0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'd0000000-0000-4000-8000-000000000004', 'credential', 'high', 'Patterns resembling tokens found in CI configuration files.', 'ci_config', 12, 'open', '{"confidence": 0.87}'::jsonb),
  ('e0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'd0000000-0000-4000-8000-000000000008', 'confidential', 'medium', 'Employment records flagged as restricted.', null, 640, 'open', '{"confidence": 0.91}'::jsonb)
on conflict (id) do nothing;

-- AI models ------------------------------------------------------------------------------
insert into public.ai_models (id, organization_id, name, provider, model_identifier, model_type, is_approved, is_external, risk_level, metadata)
values
  ('f0000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'GPT', 'OpenAI', 'gpt-example', 'chat', true, true, 'medium', '{}'::jsonb),
  ('f0000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Claude', 'Anthropic', 'claude-example', 'chat', true, true, 'medium', '{}'::jsonb),
  ('f0000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Gemini', 'Google', 'gemini-example', 'chat', false, true, 'high', '{}'::jsonb),
  ('f0000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Llama', 'Meta', 'llama-example', 'chat', true, true, 'low', '{}'::jsonb),
  ('f0000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Internal AI', 'Acme', 'internal-1', 'agent', true, false, 'low', '{}'::jsonb)
on conflict (id) do nothing;

-- AI agents ----------------------------------------------------------------------------------
insert into public.ai_agents (id, organization_id, name, description, ai_model_id, status, risk_level, metadata)
values
  ('10000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Customer Support Agent', 'Answers customer questions from CRM and docs.', 'f0000000-0000-4000-8000-000000000002', 'active', 'low', '{"owner": "Support Ops"}'::jsonb),
  ('10000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Internal Research Agent', 'Summarizes internal research material.', 'f0000000-0000-4000-8000-000000000005', 'active', 'medium', '{"owner": "Data Science"}'::jsonb),
  ('10000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Code Agent', 'Assists with code review and CI triage.', 'f0000000-0000-4000-8000-000000000001', 'paused', 'medium', '{"owner": "Engineering"}'::jsonb),
  ('10000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Finance Assistant', 'Drafts finance summaries for the finance team.', 'f0000000-0000-4000-8000-000000000005', 'active', 'high', '{"owner": "Finance"}'::jsonb)
on conflict (id) do nothing;

insert into public.ai_agent_data_permissions (agent_id, data_source_id, data_asset_id, permission_type)
values
  ('10000000-0000-4000-8000-000000000001', null, 'd0000000-0000-4000-8000-000000000001', 'read'),
  ('10000000-0000-4000-8000-000000000001', null, 'd0000000-0000-4000-8000-000000000002', 'read'),
  ('10000000-0000-4000-8000-000000000001', null, 'd0000000-0000-4000-8000-000000000003', 'read'),
  ('10000000-0000-4000-8000-000000000002', null, 'd0000000-0000-4000-8000-000000000003', 'read'),
  ('10000000-0000-4000-8000-000000000003', null, 'd0000000-0000-4000-8000-000000000004', 'read'),
  ('10000000-0000-4000-8000-000000000004', null, 'd0000000-0000-4000-8000-000000000005', 'read')
on conflict do nothing;

-- Policies ---------------------------------------------------------------------------------------
insert into public.policies (id, organization_id, name, description, status, priority, rule, action, created_by)
values
  ('20000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Customer PII Protection', 'Customer PII cannot be sent to external AI.', 'active', 10,
   '{"conditions": [{"field": "data.classification", "operator": "in", "value": ["restricted", "confidential"]}, {"field": "ai.is_external", "operator": "equals", "value": true}]}'::jsonb,
   'block', null),
  ('20000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Internal AI Access', 'Approved internal agents may access internal data.', 'active', 50,
   '{"conditions": [{"field": "ai.is_approved", "operator": "equals", "value": true}, {"field": "ai.is_external", "operator": "equals", "value": false}]}'::jsonb,
   'allow', null),
  ('20000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Financial Data Protection', 'Critical financial data cannot leave the finance boundary.', 'active', 20,
   '{"conditions": [{"field": "data.sensitivity_level", "operator": "equals", "value": "critical"}]}'::jsonb,
   'block', null)
on conflict (id) do nothing;

-- Demo AI requests (ALLOWED and BLOCKED) --------------------------------------------------------------
insert into public.ai_requests (id, organization_id, user_id, agent_id, ai_model_id, purpose, request_type, status, risk_level, metadata, created_at)
values
  ('30000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a2', null, 'f0000000-0000-4000-8000-000000000002', 'Customer Analysis', 'chat', 'blocked', 'high',
   '{"user_name": "Alex Kim", "demo": true}'::jsonb, now() - interval '2 hours'),
  ('30000000-0000-4000-8000-000000000002', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a1', '10000000-0000-4000-8000-000000000001', 'f0000000-0000-4000-8000-000000000005', 'Customer Support', 'agent_action', 'allowed', 'low',
   '{"user_name": "Sarah Chen", "demo": true}'::jsonb, now() - interval '5 hours'),
  ('30000000-0000-4000-8000-000000000003', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a3', null, 'f0000000-0000-4000-8000-000000000001', 'Code Review', 'completion', 'allowed', 'medium',
   '{"user_name": "Mike Ross", "demo": true}'::jsonb, now() - interval '1 day'),
  ('30000000-0000-4000-8000-000000000004', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a4', null, 'f0000000-0000-4000-8000-000000000003', 'Market Research', 'chat', 'review', 'high',
   '{"user_name": "Priya Shah", "demo": true}'::jsonb, now() - interval '2 days'),
  ('30000000-0000-4000-8000-000000000005', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', null, '10000000-0000-4000-8000-000000000004', 'f0000000-0000-4000-8000-000000000005', 'Finance Summary', 'agent_action', 'allowed', 'medium',
   '{"user_name": "Finance Assistant", "demo": true}'::jsonb, now() - interval '3 days'),
  ('30000000-0000-4000-8000-000000000006', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a2', null, 'f0000000-0000-4000-8000-000000000002', 'Customer Analysis', 'chat', 'blocked', 'high',
   '{"user_name": "Alex Kim", "demo": true}'::jsonb, now() - interval '4 days')
on conflict (id) do nothing;

insert into public.ai_request_data (ai_request_id, data_asset_id, access_type)
values
  ('30000000-0000-4000-8000-000000000001', 'd0000000-0000-4000-8000-000000000001', 'read'),
  ('30000000-0000-4000-8000-000000000002', 'd0000000-0000-4000-8000-000000000003', 'read'),
  ('30000000-0000-4000-8000-000000000003', 'd0000000-0000-4000-8000-000000000004', 'read'),
  ('30000000-0000-4000-8000-000000000004', 'd0000000-0000-4000-8000-000000000001', 'read'),
  ('30000000-0000-4000-8000-000000000005', 'd0000000-0000-4000-8000-000000000005', 'read'),
  ('30000000-0000-4000-8000-000000000006', 'd0000000-0000-4000-8000-000000000001', 'read')
on conflict do nothing;

insert into public.policy_evaluations (ai_request_id, policy_id, decision, reason, checks)
values
  ('30000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'block', 'Customer PII cannot be sent to external AI.',
   '{"identity": true, "permission": true, "data_classification": false, "ai_destination": false, "purpose": true}'::jsonb),
  ('30000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000002', 'allow', 'Approved internal agents may access internal data.',
   '{"identity": true, "permission": true, "data_classification": true, "ai_destination": true, "purpose": true}'::jsonb),
  ('30000000-0000-4000-8000-000000000006', '20000000-0000-4000-8000-000000000001', 'block', 'Customer PII cannot be sent to external AI.',
   '{"identity": true, "permission": true, "data_classification": false, "ai_destination": false, "purpose": true}'::jsonb)
on conflict do nothing;

insert into public.risk_events (organization_id, ai_request_id, title, description, severity, status, recommended_action, metadata)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '30000000-0000-4000-8000-000000000001', 'AI request blocked (high risk)', 'Customer PII cannot be sent to external AI.', 'high', 'open',
   'Review the triggered policies before retrying.', '{"demo": true}'::jsonb),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '30000000-0000-4000-8000-000000000004', 'AI request review (high risk)', 'Unapproved external model used with restricted data.', 'high', 'investigating',
   'Manually review this request in the audit log.', '{"demo": true}'::jsonb)
on conflict do nothing;

insert into public.audit_logs (organization_id, actor_user_id, actor_type, action, resource_type, resource_id, result, metadata)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a2', 'user', 'ai_request_blocked', 'ai_request', '30000000-0000-4000-8000-000000000001', 'blocked', '{"demo": true}'::jsonb),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'b0000000-0000-4000-8000-0000000000a1', 'ai_agent', 'ai_request_allowed', 'ai_request', '30000000-0000-4000-8000-000000000002', 'allowed', '{"demo": true}'::jsonb),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', null, 'system', 'data_asset_scanned', 'data_source', 'c0000000-0000-4000-8000-000000000003', 'success', '{"demo": true}'::jsonb)
on conflict do nothing;
