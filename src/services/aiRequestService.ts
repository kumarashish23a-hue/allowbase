import type { EvaluationResult } from '../lib/db';
import { getActiveOrganizationId, getSupabase } from '../lib/supabase';
import type { MockEvaluation } from '../utils/decision';
import { evaluateMockRequest } from '../utils/decision';
import { findAssetByLabel } from './dataAssetService';

export interface EvaluateInput {
  user: string;
  ai: string;
  data: string;
  purpose: string;
}

const decisionMap: Record<EvaluationResult['decision'], MockEvaluation['decision']> = {
  allow: 'ALLOW',
  block: 'BLOCK',
  review: 'REDACT',
};

function toMockEvaluation(result: EvaluationResult): MockEvaluation {
  return {
    decision: decisionMap[result.decision],
    reason: result.reasons.join(' ') || 'Evaluated by the Data Control Plane policy engine.',
    detected: [],
    policy: result.policies_triggered[0] ?? 'Default policy',
  };
}

async function findModelId(label: string): Promise<string | null> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return null;
  const { data, error } = await supabase.from('ai_models').select('id,name').eq('organization_id', orgId);
  if (error || !data) return null;
  const normalized = label.toLowerCase();
  const match = (data as { id: string; name: string }[]).find(
    (model) =>
      normalized.includes(model.name.toLowerCase()) || model.name.toLowerCase().includes(normalized),
  );
  return match?.id ?? null;
}

/**
 * Evaluate an AI request. Uses the Supabase Edge Function (which calls the
 * secure evaluate_ai_request Postgres function) when the app is configured
 * and the user is signed in; otherwise falls back to the local mock engine.
 */
export async function evaluateRequest(input: EvaluateInput): Promise<MockEvaluation> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (supabase && orgId) {
    try {
      const {
        data: { session },
      } = await supabase.auth.getSession();
      if (!session) return evaluateMockRequest(input);
      const [modelId, asset] = await Promise.all([findModelId(input.ai), findAssetByLabel(input.data)]);
      if (modelId && asset) {
        const { data, error } = await supabase.functions.invoke<EvaluationResult>('evaluate-ai-request', {
          body: {
            organization_id: orgId,
            ai_model_id: modelId,
            purpose: input.purpose,
            data_asset_ids: [asset.id],
          },
        });
        if (!error && data) return toMockEvaluation(data);
      }
    } catch {
      // Fall through to the mock engine below.
    }
  }
  return evaluateMockRequest(input);
}

/** Recent AI requests for the active organization. Empty when offline. */
export async function getAIRequests(limit = 20): Promise<
  { id: string; purpose: string; status: string; risk: string; created_at: string }[]
> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return [];
  const { data, error } = await supabase
    .from('ai_requests')
    .select('id,purpose,status,risk_level,created_at')
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw new Error('Could not load AI requests.');
  return (data ?? []).map((row) => ({
    id: row.id,
    purpose: row.purpose,
    status: row.status,
    risk: row.risk_level,
    created_at: row.created_at,
  }));
}
