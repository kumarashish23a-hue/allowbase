import type { Decision } from '../types';

export interface MockRequestInput {
  user: string;
  ai: string;
  data: string;
  purpose: string;
  content?: string;
}

export interface MockEvaluation {
  decision: Decision;
  reason: string;
  detected: string[];
  policy: string;
  /** True when a policy sent the request to human approval instead of deciding. */
  approvalRequired?: boolean;
  approvalRequestId?: string | null;
  /** False in monitor mode: the request was allowed but the decision was not enforced. */
  enforced?: boolean;
  /** The decision that would have applied in enforce mode (monitor mode only). */
  wouldDecision?: string | null;
  /** True when a mask policy transformed the request. */
  masked?: boolean;
  /** Content with sensitive spans redacted (only when masked is true). */
  transformedContent?: string | null;
  /** Number of spans redacted. */
  maskedCount?: number;
}

const externalModels = ['gpt', 'claude', 'gemini', 'llama'];

function includesAny(value: string, terms: string[]): boolean {
  const normalized = value.toLowerCase();
  return terms.some((term) => normalized.includes(term));
}

export function isExternalAi(ai: string): boolean {
  const normalized = ai.toLowerCase();
  if (normalized.includes('internal') || normalized.includes('approved')) return false;
  return externalModels.some((model) => normalized.includes(model));
}

export function detectSensitive(input: MockRequestInput): string[] {
  const haystack = `${input.data} ${input.purpose} ${input.content ?? ''}`.toLowerCase();
  const found: string[] = [];

  if (includesAny(haystack, ['customer database', 'customer', 'pii', 'email', 'phone', 'customer id'])) {
    found.push('PII', 'Customer IDs', 'Email addresses', 'Phone numbers');
  }
  if (includesAny(haystack, ['financial', 'finance', 'billing', 'ledger', 'revenue'])) {
    found.push('Financial records');
  }
  if (includesAny(haystack, ['credential', 'password', 'secret', 'api key', 'token'])) {
    found.push('Credentials');
  }
  if (includesAny(haystack, ['source code', 'repository', 'github'])) {
    found.push('Source code');
  }
  if (includesAny(haystack, ['employee', 'hr'])) {
    found.push('Employee records');
  }

  return Array.from(new Set(found));
}

export function evaluateMockRequest(input: MockRequestInput): MockEvaluation {
  const detected = detectSensitive(input);
  const external = isExternalAi(input.ai);
  const hasPii = detected.some((item) => ['PII', 'Customer IDs', 'Email addresses', 'Phone numbers'].includes(item));
  const hasFinancial = detected.includes('Financial records');
  const hasCredentials = detected.includes('Credentials');

  if (hasCredentials) {
    return {
      decision: 'BLOCK',
      reason: 'Credentials and secrets are never sent to AI systems.',
      detected,
      policy: 'Secrets can never leave the secure boundary.',
    };
  }

  if (hasPii && external) {
    return {
      decision: 'BLOCK',
      reason: 'Customer PII cannot be sent to external AI systems.',
      detected,
      policy: 'Customer PII cannot be sent to external AI.',
    };
  }

  if (hasFinancial && external) {
    return {
      decision: 'BLOCK',
      reason: 'Financial data cannot be sent to external AI systems.',
      detected,
      policy: 'Financial data is restricted to approved internal systems.',
    };
  }

  if (detected.length > 0 && external) {
    return {
      decision: 'REDACT',
      reason: 'Sensitive fields would be redacted before reaching the AI system.',
      detected,
      policy: 'External AI requests require redaction of sensitive fields.',
    };
  }

  if (detected.length === 0) {
    return {
      decision: 'ALLOW',
      reason: 'No sensitive data detected. Destination is approved for this purpose.',
      detected: ['No sensitive data detected'],
      policy: 'Standard internal data use policy.',
    };
  }

  return {
    decision: 'ALLOW',
    reason: 'Sensitive data stays inside the approved internal boundary with full audit logging.',
    detected,
    policy: 'Internal approved use with audit logging.',
  };
}
