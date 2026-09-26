import type { DataAssetRow } from '../lib/db';
import { getActiveOrganizationId, getSupabase } from '../lib/supabase';

export interface DataAsset {
  id: string;
  name: string;
  label: string;
  classification: string;
  sensitivity: string;
}

/** Data assets for the active organization. Empty when offline. */
export async function listDataAssets(): Promise<DataAsset[]> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const { data, error } = await supabase
    .from('data_assets')
    .select('*')
    .eq('organization_id', orgId)
    .order('name');
  if (error) throw new Error('Could not load data assets.');
  return (data as DataAssetRow[]).map((row) => ({
    id: row.id,
    name: row.name,
    label: String(row.metadata?.demo_note ?? row.name),
    classification: row.classification,
    sensitivity: row.sensitivity_level,
  }));
}

/** Fuzzy match a free-text data label (e.g. "Customer Database") to an asset. */
export async function findAssetByLabel(label: string): Promise<DataAsset | null> {
  const assets = await listDataAssets();
  const normalized = label.toLowerCase();
  return (
    assets.find(
      (asset) =>
        normalized.includes(asset.name.toLowerCase()) ||
        normalized.includes(asset.label.toLowerCase()) ||
        asset.name.toLowerCase().includes(normalized),
    ) ?? null
  );
}
