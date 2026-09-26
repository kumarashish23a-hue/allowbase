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
  /** Optional AI agent name; the request is attributed to the agent and its data permissions are enforced. */
  agent?: string;
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
    approvalRequired: result.approval_required ?? false,
    approvalRequestId: result.approval_request_id ?? null,
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

async function findAgentId(label: string | undefined): Promise<string | null> {
  if (!label || !label.trim()) return null;
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (!supabase || !orgId) return null;
  const { data, error } = await supabase.from('ai_agents').select('id,name').eq('organization_id', orgId);
  if (error || !data) return null;
  const normalized = label.trim().toLowerCase();
  const match = (data as { id: string; name: string }[]).find(
    (agent) =>
      normalized.includes(agent.name.toLowerCase()) || agent.name.toLowerCase().includes(normalized),
  );
  return match?.id ?? null;
}

/**
 * Evaluate an AI request. When the app is configured and the user is signed in
 * with a workspace, the request is evaluated by the Supabase Edge Function
 * (which calls the secure evaluate_ai_request Postgres function) and any
 * failure surfaces as an explicit error — it is never silently simulated.
 * Signed-out visitors get the local mock engine for the landing-page demo.
 */
export async function evaluateRequest(input: EvaluateInput): Promise<MockEvaluation> {
  const supabase = getSupabase();
  const orgId = await getActiveOrganizationId();
  if (supabase && orgId) {
    const {
      data: { session },
    } = await supabase.auth.getSession();
    if (!session) return evaluateMockRequest(input);

    const [modelId, asset, agentId] = await Promise.all([
      findModelId(input.ai),
      findAssetByLabel(input.data),
      findAgentId(input.agent),
    ]);
    if (!modelId || !asset) {
      throw new Error(
        'No matching AI model or data asset in your workspace. Open Account → Complete workspace setup and load the starter workspace, then try again.',
      );
    }
    if (input.agent?.trim() && !agentId) {
      throw new Error(
        `No AI agent named "${input.agent.trim()}" in your workspace. Leave the agent field empty or use an existing agent name.`,
      );
    }
    const { data, error } = await supabase.functions.invoke<EvaluationResult>('evaluate-ai-request', {
      body: {
        organization_id: orgId,
        ai_model_id: modelId,
        purpose: input.purpose,
        data_asset_ids: [asset.id],
        agent_id: agentId,
      },
    });
    if (error) {
      throw new Error(
        `Evaluation failed: ${error.message || 'the evaluation service did not respond'}. Check Account → Complete workspace setup to deploy it.`,
      );
    }
    if (!data) throw new Error('Evaluation failed: the service returned no result.');
    return toMockEvaluation(data);
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
