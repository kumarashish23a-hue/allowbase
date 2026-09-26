import { connectedSources } from '../data/mock';
import type { DataAssetRow, DataSourceRow } from '../lib/db';
import { getActiveOrganizationId, getSupabase } from '../lib/supabase';
import type { DataSource, RiskLevel } from '../types';

export interface PostgresConnectionInput {
  name: string;
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
}

export interface PostgresSourceSummary {
  id: string;
  name: string;
  type: string;
  status: string;
  host: string;
  port: number;
  database: string;
  username: string;
}

export interface DiscoverySummary {
  tables: number;
  columns: number;
  inserted: number;
  updated: number;
  truncated: boolean;
  discovered_at: string;
  findings?: number;
  columns_need_review?: number;
  classifier?: string;
}

/** Invoke an Edge Function with the active org id and surface its error message. */
async function invokeFunction<T>(
  name: string,
  body: Record<string, unknown>,
  opts?: { timeoutMs?: number; timeoutMessage?: string },
): Promise<T> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) throw new Error('Sign in to manage database connections.');
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (!session) throw new Error('Your session expired. Sign in again.');
  const invoke = (async () => {
    const result = (await supabase.functions.invoke(name, {
      body: { organization_id: orgId, ...body },
    })) as { data: T | null; error: unknown; response?: Response };
    if (result.error) {
      let message = 'The request failed. Please try again.';
      const res = result.response;
      if (res) {
        try {
          const parsed = (await res.json()) as { error?: string };
          if (parsed && typeof parsed.error === 'string' && parsed.error) message = parsed.error;
        } catch {
          /* keep the default message */
        }
      } else if (result.error instanceof Error && result.error.message) {
        message = result.error.message;
      }
      throw new Error(message);
    }
    if (!result.data) throw new Error('The service returned no result.');
    return result.data;
  })();
  if (!opts?.timeoutMs) return invoke;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      invoke,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(opts.timeoutMessage ?? 'The request took too long. Please try again.')),
          opts.timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Connect a real PostgreSQL database. Tests the connection over TLS, then
 * saves only the non-secret details. The password is used once and never stored.
 */
export async function connectPostgres(input: PostgresConnectionInput): Promise<PostgresSourceSummary> {
  const data = await invokeFunction<{ source: PostgresSourceSummary; message: string }>(
    'connect-postgres',
    {
      name: input.name,
      host: input.host,
      port: input.port,
      database: input.database,
      username: input.username,
      password: input.password,
    },
    {
      timeoutMs: 120000,
      timeoutMessage:
        'The connection test is taking unusually long. Check the connect-postgres logs in your Supabase dashboard (Edge Functions → connect-postgres → Logs), then try again.',
    },
  );
  return data.source;
}

/**
 * Discover a connected PostgreSQL source: reads table/column metadata
 * (never row data) and upserts it into the asset catalog. The password is
 * supplied per run and never stored.
 */
export async function discoverPostgres(sourceId: string, password: string): Promise<DiscoverySummary> {
  return invokeFunction<DiscoverySummary>(
    'discover-postgres',
    { source_id: sourceId, password },
    {
      timeoutMs: 120000,
      timeoutMessage:
        'Discovery is taking unusually long. Check the discover-postgres logs in your Supabase dashboard (Edge Functions → discover-postgres → Logs), then try again.',
    },
  );
}

/** Discovered table assets for one source, newest first. */
export async function listDiscoveredAssets(sourceId: string): Promise<DataAssetRow[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const { data, error } = await supabase
    .from('data_assets')
    .select('*')
    .eq('organization_id', orgId)
    .eq('data_source_id', sourceId)
    .order('name');
  if (error) throw new Error('Could not load the discovered catalog.');
  return (data ?? []) as DataAssetRow[];
}

export interface ClassifyInput {
  sourceId?: string;
  assetId?: string;
  overrides?: Array<{ column_name: string; classification: string }>;
}

export interface ClassifySummary {
  assets_processed: number;
  columns_classified: number;
  columns_need_review: number;
  findings: number;
  classifier: string;
  classified_at: string;
}

/**
 * Re-run the deterministic classifier over catalog assets (one asset, one
 * source, or everything when no scope is given). Optional overrides apply
 * manual column labels; the user's labels are never overwritten otherwise.
 */
export async function classifyAssets(input: ClassifyInput): Promise<ClassifySummary> {
  const body: Record<string, unknown> = {};
  if (input.sourceId) body.source_id = input.sourceId;
  if (input.assetId) body.asset_id = input.assetId;
  if (input.overrides) body.overrides = input.overrides;
  return invokeFunction<ClassifySummary>('classify-assets', body);
}

export interface ClassificationFinding {
  id: string;
  data_asset_id: string;
  asset_name: string;
  finding_type: string;
  severity: string;
  description: string;
  field_name: string | null;
  status: string;
  created_at: string;
}

/** Open classification findings for a source's discovered assets. */
export async function listOpenFindings(sourceId: string): Promise<ClassificationFinding[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const assets = await listDiscoveredAssets(sourceId);
  if (assets.length === 0) return [];
  const nameById = new Map(assets.map((a) => [a.id, a.name]));
  const { data, error } = await supabase
    .from('sensitive_data_findings')
    .select('id,data_asset_id,finding_type,severity,description,field_name,status,created_at')
    .eq('organization_id', orgId)
    .in('data_asset_id', assets.map((a) => a.id))
    .eq('status', 'open')
    .order('created_at', { ascending: false })
    .limit(100);
  if (error) throw new Error('Could not load classification findings.');
  return ((data ?? []) as Array<Omit<ClassificationFinding, 'asset_name'>>).map((f) => ({
    ...f,
    asset_name: nameById.get(f.data_asset_id) ?? 'Unknown table',
  }));
}

const typeCategory: Record<string, string> = {
  google_drive: 'Cloud Storage',
  github: 'Code',
  postgresql: 'Database',
  slack: 'Communication',
  notion: 'Documentation',
  aws_s3: 'Cloud Storage',
  crm: 'CRM',
  custom: 'Custom',
};

function riskFromStatus(status: string): RiskLevel {
  if (status === 'error') return 'High';
  if (status === 'disconnected') return 'Medium';
  return 'Low';
}

function toDataSource(row: DataSourceRow): DataSource {
  const metadata = row.metadata ?? {};
  const records =
    typeof metadata.records === 'string'
      ? metadata.records
      : typeof metadata.files === 'number'
        ? metadata.files.toLocaleString()
        : '—';
  const isLive = row.type === 'postgresql' && row.status === 'connected';
  return {
    id: row.id,
    name: row.name,
    category: typeCategory[row.type] ?? 'Integration',
    records,
    sensitiveAssets: typeof metadata.sensitiveAssets === 'string' ? metadata.sensitiveAssets : '—',
    lastScan: row.last_scan_at ? new Date(row.last_scan_at).toLocaleString() : '—',
    risk: riskFromStatus(row.status),
    sourceType: row.type,
    isLive,
    tableCount: typeof metadata.table_count === 'number' ? metadata.table_count : null,
  };
}

/** Data sources for the active organization; mock list when offline. */
export async function listDataSources(): Promise<DataSource[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return connectedSources;
  const { data, error } = await supabase
    .from('data_sources')
    .select('*')
    .eq('organization_id', orgId)
    .order('name');
  if (error) throw new Error('Could not load data sources.');
  return (data as DataSourceRow[]).map(toDataSource);
}
