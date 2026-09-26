import { connectedSources } from '../data/mock';
import type { DataSourceRow } from '../lib/db';
import { getActiveOrganizationId, getSupabase } from '../lib/supabase';
import type { DataSource, RiskLevel } from '../types';

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
  return {
    id: row.id,
    name: row.name,
    category: typeCategory[row.type] ?? 'Integration',
    records,
    sensitiveAssets: typeof metadata.sensitiveAssets === 'string' ? metadata.sensitiveAssets : '—',
    lastScan: row.last_scan_at ? new Date(row.last_scan_at).toLocaleString() : '—',
    risk: riskFromStatus(row.status),
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
