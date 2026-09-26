// Shared deterministic column classifier for the Data Control Plane.
// Pure TypeScript with zero dependencies so it can run in Deno Edge Functions
// and be unit-tested in Node. Implements the blueprint's classification step:
//
//   column name -> normalize -> pattern/semantic rules -> verdict
//   { classification, sensitivity, confidence, rule, evidence }
//   low-confidence or unknown columns are flagged for human review,
//   never invented with certainty.
//
// Taxonomy matches the data_assets check constraints:
//   classification: public < internal < confidential < restricted
//   sensitivity:    none < low < medium < high < critical

export type Classification = 'public' | 'internal' | 'confidential' | 'restricted';
export type Sensitivity = 'none' | 'low' | 'medium' | 'high' | 'critical';
export type FindingCategory = 'pii' | 'financial' | 'credential' | 'healthcare';

export interface ColumnVerdict {
  classification: Classification;
  sensitivity: Sensitivity;
  /** 0..1 — how sure the rule is. Below REVIEW_THRESHOLD the column needs a human. */
  confidence: number;
  /** Human-readable rule label, e.g. "Email address". */
  rule: string;
  /** Machine category used for findings. */
  category: FindingCategory | 'identifier' | 'contact' | 'technical';
  /** True when confidence is low or nothing matched. */
  needs_review: boolean;
}

export const CLASSIFIER_VERSION = 'rules-v1';
/** Confidence below this marks a column for human review (never auto-trusted). */
export const REVIEW_THRESHOLD = 0.8;

const CLASS_ORDER: Classification[] = ['public', 'internal', 'confidential', 'restricted'];
const SENS_ORDER: Sensitivity[] = ['none', 'low', 'medium', 'high', 'critical'];

export function maxClassification(a: Classification, b: Classification): Classification {
  return CLASS_ORDER.indexOf(a) >= CLASS_ORDER.indexOf(b) ? a : b;
}

export function maxSensitivity(a: Sensitivity, b: Sensitivity): Sensitivity {
  return SENS_ORDER.indexOf(a) >= SENS_ORDER.indexOf(b) ? a : b;
}

/**
 * Normalize a column name so `email`, `email_address`, `userEmail`,
 * `EMAIL-ADDRESS` and `"e-mail"` all reduce to the same comparable form.
 */
export function normalizeColumnName(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2') // camelCase -> snake_case
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_+/g, '_');
}

interface Rule {
  pattern: RegExp;
  classification: Classification;
  sensitivity: Sensitivity;
  confidence: number;
  rule: string;
  category: ColumnVerdict['category'];
}

// Ordered: first match wins. Specific patterns come before general ones
// (e.g. card_token before token, so a payment token is never labeled a credential).
const RULES: Rule[] = [
  // -- Credentials & secrets: restricted / critical -------------------------
  { pattern: /(^|_)(password|passwd|pwd_hash|pwd)(_|$)/, classification: 'restricted', sensitivity: 'critical', confidence: 0.97, rule: 'Password', category: 'credential' },
  { pattern: /(^|_)(secret|client_secret|app_secret)(_|$)/, classification: 'restricted', sensitivity: 'critical', confidence: 0.95, rule: 'Secret', category: 'credential' },
  { pattern: /(^|_)(api_key|apikey|api_secret)(_|$)/, classification: 'restricted', sensitivity: 'critical', confidence: 0.95, rule: 'API key', category: 'credential' },
  { pattern: /(^|_)(private_key|public_key|encryption_key|ssh_key)(_|$)/, classification: 'restricted', sensitivity: 'critical', confidence: 0.95, rule: 'Cryptographic key', category: 'credential' },

  // -- Financial: restricted / critical --------------------------------------
  { pattern: /(^|_)(card_number|credit_card|card_num|cc_number|cc_num)(_|$)/, classification: 'restricted', sensitivity: 'critical', confidence: 0.97, rule: 'Payment card number', category: 'financial' },
  { pattern: /(^|_)(card_token|payment_token)(_|$)/, classification: 'restricted', sensitivity: 'critical', confidence: 0.95, rule: 'Payment token', category: 'financial' },
  { pattern: /(^|_)(cvv|cvc|cvv2|cvc2|card_cvv)(_|$)/, classification: 'restricted', sensitivity: 'critical', confidence: 0.97, rule: 'Card security code', category: 'financial' },
  { pattern: /(^|_)(iban|account_number|acct_number|routing_number|sort_code|bank_account)(_|$)/, classification: 'restricted', sensitivity: 'critical', confidence: 0.95, rule: 'Bank account detail', category: 'financial' },

  // -- Auth tokens (after card/payment tokens so those win) -------------------
  { pattern: /(^|_)(auth_token|access_token|refresh_token|bearer_token|session_token|token)(_|$)/, classification: 'restricted', sensitivity: 'critical', confidence: 0.9, rule: 'Auth token', category: 'credential' },

  // -- Healthcare: restricted / high ------------------------------------------
  { pattern: /(^|_)(diagnosis|diagnoses|medical_record|health_condition|prescription|patient_record)(_|$)/, classification: 'restricted', sensitivity: 'high', confidence: 0.9, rule: 'Health record', category: 'healthcare' },

  // -- PII: confidential / high ------------------------------------------------
  { pattern: /(^|_)(email|email_address|e_mail)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.95, rule: 'Email address', category: 'pii' },
  { pattern: /(^|_)(phone|phone_number|mobile|mobile_number|telephone|cell_phone)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.9, rule: 'Phone number', category: 'pii' },
  { pattern: /(^|_)(ssn|social_security|social_security_number)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.97, rule: 'Social security number', category: 'pii' },
  { pattern: /(^|_)(passport|passport_number|driver_license|driving_licence|national_id|national_identity|aadhaar)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.95, rule: 'Government ID', category: 'pii' },
  { pattern: /(^|_)(date_of_birth|dob|birthdate|birth_date)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.95, rule: 'Date of birth', category: 'pii' },
  { pattern: /(^|_)(first_name|last_name|full_name|given_name|family_name|surname|middle_name|maiden_name)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.9, rule: 'Person name', category: 'pii' },
  { pattern: /(^|_)(address|street_address|street|zip|zipcode|zip_code|postal_code|postcode|postalcode)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.85, rule: 'Postal address', category: 'pii' },
  { pattern: /(^|_)(ip_address|ipaddress|ip)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.8, rule: 'IP address', category: 'pii' },

  // -- Financial: confidential / high (business money fields) ------------------
  { pattern: /(^|_)(salary|wage|balance|payment|revenue|payroll)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.85, rule: 'Financial amount', category: 'financial' },
  { pattern: /(^|_)(amount|total|price|cost|fee|tax|discount|subtotal)(_|$)/, classification: 'confidential', sensitivity: 'high', confidence: 0.7, rule: 'Financial amount (uncertain)', category: 'financial' },

  // -- Linkable identifiers: internal / medium ---------------------------------
  { pattern: /(^|_)(customer_id|customerid|user_id|userid|account_id|member_id|employee_id|patient_id)(_|$)/, classification: 'internal', sensitivity: 'medium', confidence: 0.75, rule: 'Linkable identifier', category: 'identifier' },
  { pattern: /^(id|uuid|guid|pk)$/, classification: 'internal', sensitivity: 'low', confidence: 0.6, rule: 'Primary key', category: 'identifier' },

  // -- Names/titles without a clear person context: uncertain -------------------
  { pattern: /^(name|title|display_name)$/, classification: 'confidential', sensitivity: 'medium', confidence: 0.65, rule: 'Name (uncertain)', category: 'contact' },

  // -- Technical / operational: internal ----------------------------------------
  { pattern: /(^|_)(is_active|is_deleted|status|state|type|kind|category|flag)(_|$)/, classification: 'internal', sensitivity: 'low', confidence: 0.6, rule: 'Operational flag', category: 'technical' },
  { pattern: /^(created_at|updated_at|created|updated|modified|deleted_at|created_on)$/, classification: 'internal', sensitivity: 'none', confidence: 0.7, rule: 'Timestamp', category: 'technical' },
  { pattern: /^(description|notes|comment|comments|remarks)$/, classification: 'internal', sensitivity: 'low', confidence: 0.6, rule: 'Free text', category: 'technical' },
];

/**
 * Classify one column. Returns null when no rule matches — the caller must
 * treat that as "unknown, needs human review", never as safe.
 */
export function classifyColumn(columnName: string): ColumnVerdict | null {
  const normalized = normalizeColumnName(columnName);
  if (!normalized) return null;
  for (const r of RULES) {
    if (r.pattern.test(normalized)) {
      return {
        classification: r.classification,
        sensitivity: r.sensitivity,
        confidence: r.confidence,
        rule: r.rule,
        category: r.category,
        needs_review: r.confidence < REVIEW_THRESHOLD,
      };
    }
  }
  return null;
}

export interface ClassifiedColumn {
  name: string;
  type?: string;
  nullable?: boolean;
  position?: number;
  classification: Classification;
  sensitivity: Sensitivity;
  confidence: number | null;
  rule: string | null;
  category: string | null;
  needs_review: boolean;
  classified_by: string; // 'rules-v1' | 'manual'
}

/** Roll an asset's classification/sensitivity up from its columns (max severity). */
export function rollupAsset(
  columns: Pick<ClassifiedColumn, 'classification' | 'sensitivity'>[],
  fallback: { classification: Classification; sensitivity: Sensitivity },
): { classification: Classification; sensitivity: Sensitivity } {
  if (columns.length === 0) return fallback;
  let c: Classification = 'public';
  let s: Sensitivity = 'none';
  for (const col of columns) {
    c = maxClassification(c, col.classification);
    s = maxSensitivity(s, col.sensitivity);
  }
  return { classification: c, sensitivity: s };
}

/** Map a classified column to a findings row, or null when not sensitive enough. */
export function columnToFinding(
  tableKey: string,
  col: ClassifiedColumn,
): { finding_type: FindingCategory | 'confidential'; severity: 'high' | 'critical'; description: string } | null {
  if (col.confidence === null) return null;
  if (col.classification !== 'confidential' && col.classification !== 'restricted') return null;
  if (col.sensitivity !== 'high' && col.sensitivity !== 'critical') return null;
  const finding_type: FindingCategory | 'confidential' =
    col.category === 'pii' || col.category === 'financial' || col.category === 'credential' || col.category === 'healthcare'
      ? col.category
      : 'confidential';
  return {
    finding_type,
    severity: col.sensitivity === 'critical' ? 'critical' : 'high',
    description:
      `${col.rule ?? 'Sensitive data'} detected in column ${tableKey}.${col.name}` +
      ` (rule-based classification, confidence ${Math.round((col.confidence ?? 0) * 100)}%).`,
  };
}
