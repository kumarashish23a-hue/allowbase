/** Database row shapes for the Data Control Plane Supabase schema. */

export interface OrganizationRow {
  id: string;
  name: string;
  slug: string;
  plan: string;
  status: string;
  /** monitor: detect and log only. enforce: policy decisions are applied. */
  enforcement_mode: 'monitor' | 'enforce';
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DataSourceRow {
  id: string;
  organization_id: string;
  name: string;
  type: string;
  status: string;
  description: string | null;
  external_id: string | null;
  metadata: Record<string, unknown>;
  last_scan_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface DataAssetRow {
  id: string;
  organization_id: string;
  data_source_id: string | null;
  name: string;
  asset_type: string;
  classification: string;
  sensitivity_level: string;
  owner_user_id: string | null;
  metadata: Record<string, unknown>;
  last_scanned_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AiModelRow {
  id: string;
  organization_id: string;
  name: string;
  provider: string;
  model_identifier: string;
  model_type: string;
  is_approved: boolean;
  is_external: boolean;
  risk_level: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface AiAgentRow {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  owner_user_id: string | null;
  ai_model_id: string | null;
  status: string;
  risk_level: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface AgentPermissionRow {
  id: string;
  agent_id: string;
  data_source_id: string | null;
  data_asset_id: string | null;
  permission_type: string;
  created_at: string;
}

export interface PolicyConditionRow {
  field: string;
  operator: string;
  value: unknown;
}

export interface PolicyRow {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  status: string;
  priority: number;
  rule: { conditions: PolicyConditionRow[] };
  action: string;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface AiRequestRow {
  id: string;
  organization_id: string;
  user_id: string | null;
  agent_id: string | null;
  ai_model_id: string | null;
  purpose: string;
  request_type: string;
  status: string;
  risk_level: string;
  source_ip: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface PolicyEvaluationRow {
  id: string;
  ai_request_id: string;
  policy_id: string;
  decision: string;
  reason: string | null;
  checks: Record<string, boolean>;
  created_at: string;
}

export interface RiskEventRow {
  id: string;
  organization_id: string;
  ai_request_id: string | null;
  data_asset_id: string | null;
  ai_agent_id: string | null;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  recommended_action: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface AuditLogRow {
  id: string;
  organization_id: string;
  actor_user_id: string | null;
  actor_type: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  result: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface DetectionFinding {
  detector: string;
  category: string;
  severity: string;
  confidence: number;
  count: number;
}

export interface EvaluationResult {
  request_id: string;
  decision: 'allow' | 'block' | 'review';
  risk: string;
  reasons: string[];
  policies_triggered: string[];
  checks: Record<string, boolean>;
  approval_required: boolean;
  approval_request_id: string | null;
  detections?: DetectionFinding[];
  /** False when the workspace is in monitor mode and the decision was not enforced. */
  enforced?: boolean;
  /** The decision that would have applied in enforce mode (monitor mode only). */
  would_decision?: 'allow' | 'block' | 'review' | null;
  enforcement_mode?: 'monitor' | 'enforce';
}
