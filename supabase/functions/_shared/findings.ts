// Shared helper: refresh the rule-based findings for one catalog asset.
// Deletes only this classifier's own OPEN findings (human-resolved or ignored
// findings are never touched), then inserts fresh ones for the classified columns.
import { CLASSIFIER_VERSION, columnToFinding } from './classify.ts';
import type { ClassifiedColumn } from './classify.ts';

export async function refreshFindings(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  supabase: any,
  organizationId: string,
  assetId: string,
  tableKey: string,
  columns: ClassifiedColumn[],
): Promise<number> {
  const { error: deleteError } = await supabase
    .from('sensitive_data_findings')
    .delete()
    .eq('data_asset_id', assetId)
    .eq('status', 'open')
    .eq('metadata->>detector', CLASSIFIER_VERSION);
  if (deleteError) {
    throw new Error('Could not clear previous classification findings.');
  }

  const rows = [];
  for (const col of columns) {
    const f = columnToFinding(tableKey, col);
    if (!f) continue;
    rows.push({
      organization_id: organizationId,
      data_asset_id: assetId,
      finding_type: f.finding_type,
      severity: f.severity,
      description: f.description,
      field_name: col.name,
      detected_count: 0,
      status: 'open',
      metadata: {
        detector: CLASSIFIER_VERSION,
        column: col.name,
        rule: col.rule,
        category: col.category,
        confidence: col.confidence,
        needs_review: col.needs_review,
        classified_by: col.classified_by,
      },
    });
  }
  if (rows.length === 0) return 0;
  const { error: insertError } = await supabase.from('sensitive_data_findings').insert(rows);
  if (insertError) {
    throw new Error('Could not record classification findings.');
  }
  return rows.length;
}
