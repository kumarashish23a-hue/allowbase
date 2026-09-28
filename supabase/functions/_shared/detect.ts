// Shared deterministic content detectors for the Data Control Plane.
// Pure TypeScript with zero dependencies so it can run in Deno Edge Functions
// and be unit-tested in Node. Implements the brief's detection pipeline step 1
// (deterministic rules) for free-text content: prompts, payloads, documents.
//
// Findings NEVER contain raw matched values — only category, severity,
// confidence, and match counts. Nothing sensitive can leak through logs,
// audit rows, or API responses via this module.
//
// Detector version is stamped on every finding so rules can evolve
// (regex-v2, ML, …) without invalidating historical records.

export type DetectionCategory =
  | 'email'
  | 'phone'
  | 'credit_card'
  | 'gov_id'
  | 'iban'
  | 'ip_address'
  | 'api_key'
  | 'private_key'
  | 'jwt'
  | 'secret';

export type DetectionSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface ContentFinding {
  /** Detector version that produced this finding, e.g. "regex-v1". */
  detector: string;
  category: DetectionCategory;
  severity: DetectionSeverity;
  /** 0..1 — how sure the rule is. */
  confidence: number;
  /** Number of matches in the scanned content (capped). */
  count: number;
}

export const DETECTOR_VERSION = 'regex-v1';
/** Findings per scan are capped so a pathological input can't blow up storage. */
export const MAX_FINDINGS_PER_CATEGORY = 99;

interface DetectorRule {
  category: DetectionCategory;
  severity: DetectionSeverity;
  confidence: number;
  pattern: RegExp;
  /** Extra validation on the raw match; return false to discard. */
  validate?: (match: string, offset: number, input: string) => boolean;
}

function luhnValid(digits: string): boolean {
  let sum = 0;
  let doubleDigit = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (doubleDigit) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
}

/** ISO 13616 mod-97 check; rejects random uppercase/digit runs that look like IBANs. */
function ibanValid(iban: string): boolean {
  if (iban.length < 15 || iban.length > 34) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const value = code >= 65 && code <= 90 ? String(code - 55) : ch;
    for (const digit of value) {
      remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
  }
  return remainder === 1;
}

const RULES: DetectorRule[] = [
  {
    category: 'email',
    severity: 'medium',
    confidence: 0.9,
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    validate: (m) => {
      // Reject obvious non-emails: file names, version strings.
      const tld = m.slice(m.lastIndexOf('.') + 1).toLowerCase();
      return tld.length <= 6 && !/^(png|jpg|jpeg|gif|svg|exe|dll|json)$/.test(tld);
    },
  },
  {
    category: 'phone',
    severity: 'medium',
    confidence: 0.75,
    pattern: /(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,5}\)[\s-]?|\d{2,5}[\s-])\d{3,4}[\s-]?\d{3,4}\b/g,
    validate: (m, offset, input) => {
      const digits = m.replace(/\D/g, '');
      if (digits.length < 7 || digits.length > 15) return false;
      // Reject matches embedded in a longer digit run (e.g. inside a card
      // number): look past any separators on either side for more digits.
      const before = input.slice(0, offset).replace(/[\s()-]*$/, '');
      const after = input.slice(offset + m.length).replace(/^[\s()-]*/, '');
      return !/\d$/.test(before) && !/^\d/.test(after);
    },
  },
  {
    category: 'credit_card',
    severity: 'high',
    confidence: 0.98,
    pattern: /\b(?:\d[ -]?){13,19}\b/g,
    validate: (m) => {
      const digits = m.replace(/\D/g, '');
      return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
    },
  },
  {
    category: 'gov_id',
    severity: 'high',
    confidence: 0.9,
    // US SSN shape; other national IDs can be added as separate rules.
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    category: 'iban',
    severity: 'high',
    confidence: 0.95,
    pattern: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g,
    validate: (m) => ibanValid(m.replace(/ /g, '')),
  },
  {
    category: 'ip_address',
    severity: 'low',
    confidence: 0.7,
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    validate: (m, offset, input) => {
      if (!m.split('.').every((octet) => Number(octet) <= 255 && !(octet.length > 1 && octet.startsWith('0')))) {
        return false;
      }
      // Skip version strings (v1.2.3.4) and longer dotted runs (1.2.3.4.5).
      const before = input.slice(Math.max(0, offset - 1), offset);
      const after = input.slice(offset + m.length, offset + m.length + 2);
      return !/[vV.]/.test(before) && !/^\.\d/.test(after);
    },
  },
  {
    category: 'api_key',
    severity: 'critical',
    confidence: 1.0,
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    category: 'api_key',
    severity: 'critical',
    confidence: 0.98,
    // OpenAI (sk-..., sk-proj-...) and Anthropic (sk-ant-...) keys.
    pattern: /\bsk-(?:proj-|ant-(?:api\d{2}-)?)?[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    category: 'api_key',
    severity: 'critical',
    confidence: 0.98,
    pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    category: 'api_key',
    severity: 'critical',
    confidence: 0.95,
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    category: 'api_key',
    severity: 'critical',
    confidence: 1.0,
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  },
  {
    category: 'api_key',
    severity: 'critical',
    confidence: 1.0,
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g,
  },
  {
    category: 'private_key',
    severity: 'critical',
    confidence: 1.0,
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    category: 'jwt',
    severity: 'high',
    confidence: 0.9,
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    category: 'secret',
    severity: 'critical',
    confidence: 0.8,
    // No \b: keywords often appear as db_password or api-key assignments.
    pattern: /(?:^|[^A-Za-z0-9])(?:password|passwd|pwd|secret|api[_-]?key|client[_-]?secret|aws_secret_access_key)\s*[:=]\s*['"]?[^\s'";,]{8,64}['"]?/gi,
  },
];

/**
 * Scan free-text content for sensitive patterns.
 * Returns one finding per detected category (never raw matched values).
 * Empty or non-text input yields no findings.
 */
export function detectSensitiveContent(content: string): ContentFinding[] {
  if (typeof content !== 'string' || content.length === 0) return [];
  const findings: ContentFinding[] = [];
  const seen = new Set<DetectionCategory>();

  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    let count = 0;
    let match: RegExpExecArray | null;
    // Bound the scan so adversarial input can't spin forever.
    let steps = 0;
    while ((match = rule.pattern.exec(content)) !== null && steps < 10000) {
      steps++;
      if (match[0].length === 0) {
        rule.pattern.lastIndex++;
        continue;
      }
      if (!rule.validate || rule.validate(match[0], match.index, content)) {
        count++;
        if (count >= MAX_FINDINGS_PER_CATEGORY) break;
      }
    }
    if (count > 0 && !seen.has(rule.category)) {
      seen.add(rule.category);
      findings.push({
        detector: DETECTOR_VERSION,
        category: rule.category,
        severity: rule.severity,
        confidence: rule.confidence,
        count,
      });
    } else if (count > 0) {
      // Same category from a second rule (e.g. two api_key shapes): merge counts.
      const existing = findings.find((f) => f.category === rule.category);
      if (existing) {
        existing.count = Math.min(MAX_FINDINGS_PER_CATEGORY, existing.count + count);
        existing.confidence = Math.max(existing.confidence, rule.confidence);
        if (severityRank(rule.severity) > severityRank(existing.severity)) {
          existing.severity = rule.severity;
        }
      }
    }
  }
  return findings;
}

function severityRank(s: DetectionSeverity): number {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s];
}

/** True when any finding is critical-severity (secrets, private keys, API keys). */
export function hasCriticalFinding(findings: ContentFinding[]): boolean {
  return findings.some((f) => f.severity === 'critical');
}

/** Distinct categories present, for policy matching and audit metadata. */
export function findingCategories(findings: ContentFinding[]): DetectionCategory[] {
  return [...new Set(findings.map((f) => f.category))];
}

export interface MaskResult {
  /** The content with every detected sensitive span replaced. */
  masked: string;
  /** Number of spans replaced. */
  maskedCount: number;
  /** Categories that were masked. */
  categories: DetectionCategory[];
}

interface MaskSpan {
  start: number;
  end: number;
  category: DetectionCategory;
}

/**
 * Replace every detected sensitive span with `[redacted:category]`.
 * Raw matched values never leave this function — callers only see the
 * transformed string plus aggregate counts, so masked output is safe to
 * return in API responses and display in the UI.
 */
export function maskSensitiveContent(content: string): MaskResult {
  if (typeof content !== 'string' || content.length === 0) {
    return { masked: content, maskedCount: 0, categories: [] };
  }
  const spans: MaskSpan[] = [];
  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    // Same bound as detection so adversarial input can't spin forever.
    let steps = 0;
    while ((match = rule.pattern.exec(content)) !== null && steps < 10000) {
      steps++;
      if (match[0].length === 0) {
        rule.pattern.lastIndex++;
        continue;
      }
      if (!rule.validate || rule.validate(match[0], match.index, content)) {
        spans.push({ start: match.index, end: match.index + match[0].length, category: rule.category });
      }
    }
  }
  // Prefer earlier, longer spans; drop anything overlapping an accepted span.
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  const accepted: MaskSpan[] = [];
  for (const span of spans) {
    if (accepted.some((s) => span.start < s.end && s.start < span.end)) continue;
    accepted.push(span);
  }
  accepted.sort((a, b) => a.start - b.start);
  let masked = '';
  let cursor = 0;
  for (const span of accepted) {
    masked += content.slice(cursor, span.start);
    masked += `[redacted:${span.category}]`;
    cursor = span.end;
  }
  masked += content.slice(cursor);
  return {
    masked,
    maskedCount: accepted.length,
    categories: [...new Set(accepted.map((s) => s.category))],
  };
}
