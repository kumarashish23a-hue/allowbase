import { getActiveOrganizationId, getLocalUserId, getSupabase, isSupabaseConfigured } from '../lib/supabase';

export type EdgeFunctionStatus = 'deployed' | 'missing' | 'unknown';

export interface MigrationStatus {
  state: 'ok' | 'missing' | 'unknown';
  /** Migration files (under supabase/migrations/) that still need to be run, in order. */
  missingFiles: string[];
}

export interface SetupStatus {
  configured: boolean;
  signedIn: boolean;
  hasOrg: boolean;
  orgName: string | null;
  /** Optional industry label stored on organizations.settings. */
  industry: string | null;
  enforcementMode: 'monitor' | 'enforce' | null;
  migrations: MigrationStatus;
  /** True when the org already has models, assets, or policies. */
  hasData: boolean;
  /** AI models registered for the org (destinations the policies can target). */
  models: { name: string; provider: string | null }[];
  /** True when at least one data source is connected. */
  hasDataSource: boolean;
  /** True when at least one agent is registered. */
  hasAgent: boolean;
  functions: Record<'evaluate-ai-request' | 'ingest-event' | 'ai-provider' | 'ai-gateway', EdgeFunctionStatus>;
  /** True when at least one non-revoked API key exists. */
  hasApiKey: boolean;
  /** True when at least one AI request has been recorded. */
  hasRequests: boolean;
}

export const EDGE_FUNCTION_NAME = 'evaluate-ai-request';
export const INGEST_FUNCTION_NAME = 'ingest-event';
export const PROVIDER_FUNCTION_NAME = 'ai-provider';
export const GATEWAY_FUNCTION_NAME = 'ai-gateway';

/**
 * True when the user-facing "connect everything" steps are done: organization,
 * AI provider, data source, apps/agents, and a security mode on the workspace.
 * Used by the console gate and post-sign-in flow so a signed-in user connects
 * everything before the dashboard. (The org always carries a mode from
 * migration 015, so this is really the four connection steps.)
 */
export function setupConnectComplete(status: SetupStatus): boolean {
  return (
    status.hasOrg &&
    status.models.length > 0 &&
    status.hasDataSource &&
    (status.hasAgent || status.hasApiKey) &&
    status.enforcementMode !== null
  );
}

/**
 * getSetupStatus() with a hard timeout. The status check fans out to several
 * PostgREST queries and edge-function probes; any one of them can stall at
 * the network level and hang the caller forever. Returns null on timeout so
 * callers can fail open (dashboard) or show a retry instead of spinning.
 */
export async function getSetupStatusSafe(timeoutMs = 15000): Promise<SetupStatus | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), timeoutMs);
    });
    return await Promise.race([getSetupStatus(), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
const EDGE_FUNCTION_CODE_URL =
  'https://raw.githubusercontent.com/kumarashish23a-hue/allowbase/main/supabase/functions/evaluate-ai-request/index.ts';

/** Tables (and columns) that prove their migration has been applied, and the file to run if not. */
const MIGRATION_TABLES: { table: string; column?: string; file: string }[] = [  { table: 'organizations', file: '001_core.sql → 009_seed.sql' },
  { table: 'ai_requests', file: '005_requests.sql' },
  { table: 'approval_requests', file: '010_hardening.sql' },
  { table: 'api_keys', file: '011_api_keys.sql' },
  { table: 'ai_requests', column: 'detection_findings', file: '012_content_detection.sql' },
  { table: 'organization_members', column: 'force_logout_at', file: '014_force_logout.sql' },
  { table: 'organizations', column: 'enforcement_mode', file: '015_enforcement_mode.sql' },
  { table: 'ai_provider_connections', file: '017_provider_connections.sql' },
];

/** Every migration file in apply order. */
const MIGRATION_FILES_IN_ORDER = [
  '001_core.sql',
  '002_data.sql',
  '003_ai.sql',
  '004_policies.sql',
  '005_requests.sql',
  '006_risk_audit.sql',
  '007_rls.sql',
  '008_functions.sql',
  '009_seed.sql',
  '010_hardening.sql',
  '011_api_keys.sql',
  '012_content_detection.sql',
  '013_admin_member_reads.sql',
  '014_force_logout.sql',
  '015_enforcement_mode.sql',
  '016_mask_action.sql',
  '017_provider_connections.sql',
  '018_dashboard_graphs.sql',
  '019_provider_condition.sql',
];

const MIGRATION_RAW_BASE =
  'https://raw.githubusercontent.com/kumarashish23a-hue/allowbase/main/supabase/migrations/';

/**
 * Expand the wizard's missing-file entries (which may be ranges like
 * '001_core.sql → 009_seed.sql') into the ordered list of individual files.
 */
export function expandMissingFiles(missingFiles: string[]): string[] {
  const out: string[] = [];
  for (const entry of missingFiles) {
    if (entry.includes('→')) {
      const [from, to] = entry.split('→').map((s) => s.trim());
      const start = MIGRATION_FILES_IN_ORDER.indexOf(from);
      const end = MIGRATION_FILES_IN_ORDER.indexOf(to);
      if (start !== -1 && end !== -1 && end >= start) {
        out.push(...MIGRATION_FILES_IN_ORDER.slice(start, end + 1));
      }
    } else if (MIGRATION_FILES_IN_ORDER.includes(entry)) {
      out.push(entry);
    }
  }
  return [...new Set(out)];
}

/**
 * Fetch every pending migration and bundle them into ONE sql script, in
 * order — so setup is a single copy-paste into the SQL editor.
 */
export async function fetchPendingMigrationsSQL(missingFiles: string[]): Promise<string> {
  const files = expandMissingFiles(missingFiles);
  if (files.length === 0) throw new Error('Nothing to copy — the database is up to date.');
  const parts: string[] = [];
  for (const file of files) {
    const res = await fetch(`${MIGRATION_RAW_BASE}${file}`);
    if (!res.ok) throw new Error(`Could not download ${file} from GitHub.`);
    const sql = (await res.text()).trim();
    parts.push(`-- =================================================================\n-- ${file}\n-- =================================================================\n${sql}`);
  }
  return parts.join('\n\n');
}

/** Check which migrations are missing by probing for their tables. Never throws. */
async function checkMigrations(
  supabase: NonNullable<ReturnType<typeof getSupabase>>,
): Promise<MigrationStatus> {
  const missingFiles: string[] = [];
  for (const { table, column, file } of MIGRATION_TABLES) {
    const { error } = await supabase.from(table).select(column ?? 'id', { head: true }).limit(1);
    if (!error) continue;
    // 42P01 = table missing, 42703 = column missing (a later migration not applied).
    if ((error as { code?: string }).code === '42P01' || (error as { code?: string }).code === '42703') {
      if (!missingFiles.includes(file)) missingFiles.push(file);
      continue;
    }
    // A real error (RLS, network…) — don't claim anything is missing.
    return { state: 'unknown', missingFiles: [] };
  }
  return missingFiles.length > 0
    ? { state: 'missing', missingFiles }
    : { state: 'ok', missingFiles: [] };
}

/** Full setup checklist state for the current user. */
export async function getSetupStatus(): Promise<SetupStatus> {
  const fallback: SetupStatus = {
    configured: isSupabaseConfigured(),
    signedIn: false,
    hasOrg: false,
    orgName: null,
    industry: null,
    enforcementMode: null,
    migrations: { state: 'unknown', missingFiles: [] },
    hasData: false,
    models: [],
    hasDataSource: false,
    hasAgent: false,
    functions: { 'evaluate-ai-request': 'unknown', 'ingest-event': 'unknown', 'ai-provider': 'unknown', 'ai-gateway': 'unknown' },
    hasApiKey: false,
    hasRequests: false,
  };
  const supabase = getSupabase();
  if (!supabase) return fallback;
  // getSession() reads the local session and never hangs; auth.getUser() hits
  // the network and can stall during token-refresh races (same class of hang
  // as the old admin gate). RLS still validates the token server-side.
  const userId = await getLocalUserId();
  if (!userId) return fallback;

  const { data: memberships } = await supabase
    .from('organization_members')
    .select('organization_id, organizations ( name )')
    .eq('user_id', userId)
    .eq('status', 'active')
    .limit(1);
  const first = (memberships as { organization_id: string; organizations: { name: string } | null }[] | null)?.[0];
  if (!first) return { ...fallback, signedIn: true };

  const orgId = first.organization_id;
  const [models, assets, policies, keys, requests, migrations, evaluateFn, ingestFn, providerFn, gatewayFn, orgRow, modelRows, sourceCount, agentCount] = await Promise.all([
    supabase.from('ai_models').select('id', { count: 'exact', head: true }).eq('organization_id', orgId),
    supabase.from('data_assets').select('id', { count: 'exact', head: true }).eq('organization_id', orgId),
    supabase.from('policies').select('id', { count: 'exact', head: true }).eq('organization_id', orgId),
    supabase
      .from('api_keys')
      .select('id', { count: 'exact', head: true })
      .eq('organization_id', orgId)
      .is('revoked_at', null),
    supabase.from('ai_requests').select('id', { count: 'exact', head: true }).eq('organization_id', orgId),
    checkMigrations(supabase),
    probeEdgeFunction(EDGE_FUNCTION_NAME),
    probeEdgeFunction(INGEST_FUNCTION_NAME),
    probeEdgeFunction(PROVIDER_FUNCTION_NAME),
    probeEdgeFunction(GATEWAY_FUNCTION_NAME),
    supabase.from('organizations').select('settings,enforcement_mode').eq('id', orgId).maybeSingle(),
    supabase.from('ai_models').select('name,provider').eq('organization_id', orgId).limit(10),
    supabase.from('data_sources').select('id', { count: 'exact', head: true }).eq('organization_id', orgId),
    supabase.from('ai_agents').select('id', { count: 'exact', head: true }).eq('organization_id', orgId),
  ]);
  const hasData = (models.count ?? 0) + (assets.count ?? 0) + (policies.count ?? 0) > 0;
  const settings = (orgRow.data?.settings ?? {}) as Record<string, unknown>;
  return {
    configured: true,
    signedIn: true,
    hasOrg: true,
    orgName: first.organizations?.name ?? null,
    industry: typeof settings.industry === 'string' ? (settings.industry as string) : null,
    enforcementMode:
      orgRow.data?.enforcement_mode === 'enforce' ? 'enforce'
      : orgRow.data?.enforcement_mode === 'monitor' ? 'monitor'
      : null,
    migrations,
    hasData,
    models: (modelRows.data ?? []).map((m) => ({ name: m.name, provider: m.provider })),
    hasDataSource: (sourceCount.count ?? 0) > 0,
    hasAgent: (agentCount.count ?? 0) > 0,
    functions: { 'evaluate-ai-request': evaluateFn, 'ingest-event': ingestFn, 'ai-provider': providerFn, 'ai-gateway': gatewayFn },
    hasApiKey: (keys.count ?? 0) > 0,
    hasRequests: (requests.count ?? 0) > 0,
  };
}

/**
 * Probe whether an Edge Function is deployed.
 * Sends an empty body: a deployed function answers 400/401 (validation),
 * a missing one answers 404. No database side effects either way.
 */
export async function probeEdgeFunction(functionName: string): Promise<EdgeFunctionStatus> {
  const supabase = getSupabase();
  if (!supabase) return 'unknown';
  try {
    const { error } = await supabase.functions.invoke(functionName, { body: {} });
    if (!error) return 'deployed';
    const status = (error as { context?: { status?: number } }).context?.status;
    const message = String((error as Error).message ?? '').toLowerCase();
    if (status === 404 || message.includes('not found')) return 'missing';
    // 400/401/500 all prove the function exists and answered.
    return 'deployed';
  } catch {
    return 'unknown';
  }
}

export interface StarterDataSummary {
  sources: number;
  assets: number;
  models: number;
  agents: number;
  policies: number;
  findings: number;
}

/**
 * Insert the starter workspace (sources, assets, models, agent, policies,
 * finding) for the active organization via the normal API, honoring RLS.
 * Only fills categories that are currently empty. Requires the caller to be
 * signed in as org owner/admin/security.
 */
export async function loadStarterData(): Promise<StarterDataSummary> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) throw new Error('Sign in and create an organization first.');
  const summary: StarterDataSummary = { sources: 0, assets: 0, models: 0, agents: 0, policies: 0, findings: 0 };

  const { count: sourceCount } = await supabase
    .from('data_sources')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId);
  let sourceIds: Record<string, string> = {};
  if ((sourceCount ?? 0) === 0) {
    const { data, error } = await supabase
      .from('data_sources')
      .insert([
        { organization_id: orgId, name: 'PostgreSQL', type: 'postgresql', status: 'demo', description: 'Primary application database.' },
        { organization_id: orgId, name: 'Google Drive', type: 'google_drive', status: 'demo', description: 'Company documents and shared drives.' },
      ])
      .select('id,type');
    if (error) throw new Error('Could not create data sources.');
    for (const row of data ?? []) sourceIds[row.type] = row.id;
    summary.sources = data?.length ?? 0;
  } else {
    const { data } = await supabase.from('data_sources').select('id,type').eq('organization_id', orgId);
    for (const row of data ?? []) sourceIds[row.type] = row.id;
  }

  const { count: assetCount } = await supabase
    .from('data_assets')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId);
  let customerDbId: string | null = null;
  if ((assetCount ?? 0) === 0) {
    const { data, error } = await supabase
      .from('data_assets')
      .insert([
        {
          organization_id: orgId,
          data_source_id: sourceIds['postgresql'] ?? null,
          name: 'Customer Database',
          asset_type: 'table',
          classification: 'restricted',
          sensitivity_level: 'high',
          metadata: { demo_note: 'Customer Database' },
        },
        {
          organization_id: orgId,
          data_source_id: sourceIds['google_drive'] ?? null,
          name: 'Product Documentation',
          asset_type: 'document',
          classification: 'internal',
          sensitivity_level: 'low',
          metadata: {},
        },
      ])
      .select('id,name');
    if (error) throw new Error('Could not create data assets.');
    customerDbId = (data ?? []).find((row) => row.name === 'Customer Database')?.id ?? null;
    summary.assets = data?.length ?? 0;
  } else {
    const { data } = await supabase
      .from('data_assets')
      .select('id,name')
      .eq('organization_id', orgId)
      .eq('name', 'Customer Database')
      .limit(1);
    customerDbId = data?.[0]?.id ?? null;
  }

  const { count: modelCount } = await supabase
    .from('ai_models')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId);
  let internalModelId: string | null = null;
  if ((modelCount ?? 0) === 0) {
    const { data, error } = await supabase
      .from('ai_models')
      .insert([
        { organization_id: orgId, name: 'Claude', provider: 'Anthropic', model_identifier: 'claude-4', model_type: 'chat', is_approved: true, is_external: true, risk_level: 'medium' },
        { organization_id: orgId, name: 'Internal Support Agent', provider: 'Internal', model_identifier: 'internal-support-1', model_type: 'chat', is_approved: true, is_external: false, risk_level: 'low' },
      ])
      .select('id,name');
    if (error) throw new Error('Could not create AI models.');
    internalModelId = (data ?? []).find((row) => row.name === 'Internal Support Agent')?.id ?? null;
    summary.models = data?.length ?? 0;
  } else {
    const { data } = await supabase
      .from('ai_models')
      .select('id,name')
      .eq('organization_id', orgId)
      .eq('name', 'Internal Support Agent')
      .limit(1);
    internalModelId = data?.[0]?.id ?? null;
  }

  const { count: agentCount } = await supabase
    .from('ai_agents')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId);
  if ((agentCount ?? 0) === 0) {
    const { data, error } = await supabase
      .from('ai_agents')
      .insert([
        {
          organization_id: orgId,
          name: 'Customer Support Agent',
          description: 'Answers customer questions from docs and tickets.',
          ai_model_id: internalModelId,
          status: 'active',
          risk_level: 'low',
          metadata: { owner: 'Support' },
        },
      ])
      .select('id');
    if (error) throw new Error('Could not create the starter agent.');
    summary.agents = data?.length ?? 0;
  }

  const { count: policyCount } = await supabase
    .from('policies')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId);
  if ((policyCount ?? 0) === 0) {
    const { data, error } = await supabase.from('policies').insert([
      {
        organization_id: orgId,
        name: 'Block Secrets in AI Content',
        description: 'API keys, private keys, and passwords detected in request content are blocked outright.',
        status: 'active',
        priority: 5,
        rule: {
          conditions: [
            { field: 'content.category', operator: 'in', value: ['secret', 'private_key', 'api_key'] },
          ],
        },
        action: 'block',
      },
      {
        organization_id: orgId,
        name: 'Customer PII Protection',
        description: 'Restricted customer data cannot be sent to external AI.',
        status: 'active',
        priority: 10,
        rule: {
          conditions: [
            { field: 'data.classification', operator: 'in', value: ['restricted', 'confidential'] },
            { field: 'ai.is_external', operator: 'equals', value: true },
          ],
        },
        action: 'block',
      },
      {
        organization_id: orgId,
        name: 'Internal AI Access',
        description: 'Approved internal models may access internal data.',
        status: 'active',
        priority: 50,
        rule: {
          conditions: [
            { field: 'ai.is_approved', operator: 'equals', value: true },
            { field: 'ai.is_external', operator: 'equals', value: false },
          ],
        },
        action: 'allow',
      },
    ]).select('id');
    if (error) throw new Error('Could not create starter policies.');
    summary.policies = data?.length ?? 0;
    // The mask policy needs migration 016. On older databases the insert is
    // skipped instead of failing the whole starter load.
    try {
      const { data: maskData, error: maskError } = await supabase.from('policies').insert([
        {
          organization_id: orgId,
          name: 'Mask PII in AI Content',
          description: 'Emails, phone numbers, credit cards, and IDs detected in request content are redacted before forwarding.',
          status: 'active',
          priority: 7,
          rule: {
            conditions: [
              { field: 'content.category', operator: 'in', value: ['email', 'phone', 'credit_card', 'gov_id'] },
            ],
          },
          action: 'mask',
        },
      ]).select('id');
      if (!maskError) summary.policies += maskData?.length ?? 0;
    } catch {
      // Migration 016 not applied yet — the workspace still loads.
    }
  }

  const { count: findingCount } = await supabase
    .from('sensitive_data_findings')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId);
  if ((findingCount ?? 0) === 0 && customerDbId) {
    const { data, error } = await supabase.from('sensitive_data_findings').insert([
      {
        organization_id: orgId,
        data_asset_id: customerDbId,
        finding_type: 'pii',
        severity: 'high',
        description: 'Customer identifiers and contact fields detected.',
        field_name: 'email_address',
        detected_count: 128400,
        status: 'open',
        metadata: { confidence: 0.98 },
      },
    ]).select('id');
    if (error) throw new Error('Could not create the starter finding.');
    summary.findings = data?.length ?? 0;
  }

  return summary;
}

/** Deep link to the Supabase dashboard's Functions page for this project. */
export function getFunctionsDashboardUrl(): string | null {
  if (!isSupabaseConfigured()) return null;
  try {
    const url = import.meta.env.VITE_SUPABASE_URL as string;
    const ref = new URL(url).hostname.split('.')[0];
    if (!ref) return null;
    return `https://supabase.com/dashboard/project/${ref}/functions`;
  } catch {
    return null;
  }
}

/** Deep link to the Supabase dashboard's SQL editor for this project. */
export function getSqlEditorUrl(): string | null {
  if (!isSupabaseConfigured()) return null;
  try {
    const url = import.meta.env.VITE_SUPABASE_URL as string;
    const ref = new URL(url).hostname.split('.')[0];
    if (!ref) return null;
    return `https://supabase.com/dashboard/project/${ref}/sql/new`;
  } catch {
    return null;
  }
}
/** Fetch the Edge Function source so the user can copy-paste it into the dashboard. */
export async function fetchEdgeFunctionCode(): Promise<string> {
  const res = await fetch(EDGE_FUNCTION_CODE_URL);
  if (!res.ok) throw new Error('Could not download the function code.');
  return res.text();
}
