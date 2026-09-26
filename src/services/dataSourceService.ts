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
}

/** Invoke an Edge Function with the active org id and surface its error message. */
async function invokeFunction<T>(name: string, body: Record<string, unknown>): Promise<T> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) throw new Error('Sign in to manage database connections.');
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (!session) throw new Error('Your session expired. Sign in again.');
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
}

/**
 * Connect a real PostgreSQL database. Tests the connection over TLS, then
 * saves only the non-secret details. The password is used once and never stored.
 */
export async function connectPostgres(input: PostgresConnectionInput): Promise<PostgresSourceSummary> {
  const data = await invokeFunction<{ source: PostgresSourceSummary; message: string }>('connect-postgres', {
    name: input.name,
    host: input.host,
    port: input.port,
    database: input.database,
    username: input.username,
    password: input.password,
  });
  return data.source;
}

/**
 * Discover a connected PostgreSQL source: reads table/column metadata
 * (never row data) and upserts it into the asset catalog. The password is
 * supplied per run and never stored.
 */
export async function discoverPostgres(sourceId: string, password: string): Promise<DiscoverySummary> {
  return invokeFunction<DiscoverySummary>('discover-postgres', { source_id: sourceId, password });
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
