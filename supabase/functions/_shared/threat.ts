// Shared deterministic threat detectors for AllowBase.
// Pure TypeScript with zero dependencies so it can run in Deno Edge Functions
// and be unit-tested in Node. Implements the brief's threat-detection layer
// with deterministic rules first: prompt injection, jailbreaks, system-prompt
// extraction, exfiltration attempts, malicious instructions, and suspicious
// tool calls.
//
// Findings NEVER contain raw matched values — only category, severity,
// confidence, and match counts. The detector version is stamped on every
// finding ('threat-v1') so the policy engine can distinguish threat findings
// from content findings (see the threat.category branch in
// policy_condition_matches).

export type ThreatCategory =
  | 'prompt_injection'
  | 'jailbreak'
  | 'system_prompt_extraction'
  | 'exfiltration_attempt'
  | 'malicious_instruction'
  | 'suspicious_tool_call';

export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface ThreatFinding {
  /** Detector version that produced this finding, e.g. "threat-v1". */
  detector: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  /** 0..1 — how sure the rule is. */
  confidence: number;
  /** Number of matches in the scanned content (capped). */
  count: number;
}

export const THREAT_DETECTOR_VERSION = 'threat-v1';
/** Findings per scan are capped so a pathological input can't blow up storage. */
export const MAX_THREAT_FINDINGS_PER_CATEGORY = 99;

export const THREAT_CATEGORIES: ThreatCategory[] = [
  'prompt_injection',
  'jailbreak',
  'system_prompt_extraction',
  'exfiltration_attempt',
  'malicious_instruction',
  'suspicious_tool_call',
];

interface ThreatRule {
  category: ThreatCategory;
  severity: ThreatSeverity;
  confidence: number;
  pattern: RegExp;
  /** Extra validation on the raw match; return false to discard. */
  validate?: (match: string, offset: number, input: string) => boolean;
}

const URL_PATTERN = /https?:\/\/[^\s"'<>]+|webhook/i;

const RULES: ThreatRule[] = [
  // -- prompt_injection -------------------------------------------------------
  {
    category: 'prompt_injection',
    severity: 'high',
    confidence: 0.9,
    pattern: /ignore\s+(all\s+)?(previous|prior)\s+instructions?/gi,
  },
  {
    category: 'prompt_injection',
    severity: 'high',
    confidence: 0.9,
    pattern: /disregard\s+(all\s+)?your\s+(previous|prior|system)\s+(instructions?|directives?|prompt)/gi,
  },
  {
    category: 'prompt_injection',
    severity: 'high',
    confidence: 0.85,
    pattern: /forget\s+(all\s+)?(your|the)\s+(previous|prior|system)\s+(instructions?|rules?)/gi,
  },
  {
    category: 'prompt_injection',
    severity: 'high',
    confidence: 0.9,
    pattern: /override\s+your\s+(system\s+)?instructions?/gi,
  },
  {
    category: 'prompt_injection',
    severity: 'high',
    confidence: 0.7,
    // "You are now a pirate" — role reassignment aimed at the AI itself.
    pattern: /you\s+are\s+now\s+(a|an)\s+[a-z]/gi,
  },
  {
    category: 'prompt_injection',
    severity: 'high',
    confidence: 0.9,
    pattern: /do\s+not\s+follow\s+(your|the)\s+(system|original|initial)\s+(instructions?|prompt|rules?)/gi,
  },
  {
    category: 'prompt_injection',
    severity: 'high',
    confidence: 0.9,
    pattern: /bypass\s+your\s+(safety|content)\s+(filters?|policy|guidelines?)/gi,
  },
  {
    category: 'prompt_injection',
    severity: 'high',
    confidence: 0.85,
    pattern: /act\s+as\s+if\s+you\s+(have|had)\s+no\s+(rules?|restrictions?|guidelines?|limits?)/gi,
  },
  // -- jailbreak --------------------------------------------------------------
  {
    category: 'jailbreak',
    severity: 'high',
    confidence: 0.9,
    pattern: /do\s+anything\s+now/gi,
  },
  {
    category: 'jailbreak',
    severity: 'high',
    confidence: 0.95,
    pattern: /\bdan\s+mode\b/gi,
  },
  {
    category: 'jailbreak',
    severity: 'high',
    confidence: 0.9,
    pattern: /\bjailbreak\b/gi,
  },
  {
    category: 'jailbreak',
    severity: 'high',
    confidence: 0.85,
    // Imperative phrasing only ("enable developer mode") — the declarative
    // "developer mode enabled us to…" is benign discussion, not an attack.
    pattern: /(enable|activate|enter)\s+developer\s+mode/gi,
  },
  {
    category: 'jailbreak',
    severity: 'high',
    confidence: 0.85,
    pattern: /unrestricted\s+mode/gi,
  },
  {
    category: 'jailbreak',
    severity: 'high',
    confidence: 0.8,
    pattern: /no\s+(rules?|restrictions?|filters?)\s+apply/gi,
  },
  // -- system_prompt_extraction ------------------------------------------------
  {
    category: 'system_prompt_extraction',
    severity: 'medium',
    confidence: 0.9,
    pattern: /reveal\s+your\s+(system\s+)?(prompt|instructions?)/gi,
  },
  {
    category: 'system_prompt_extraction',
    severity: 'medium',
    confidence: 0.9,
    pattern: /repeat\s+your\s+(system\s+)?(prompt|instructions?)/gi,
  },
  {
    category: 'system_prompt_extraction',
    severity: 'medium',
    confidence: 0.9,
    pattern: /what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?)/gi,
  },
  {
    category: 'system_prompt_extraction',
    severity: 'medium',
    confidence: 0.9,
    pattern: /show\s+me\s+your\s+(system\s+)?prompt/gi,
  },
  {
    category: 'system_prompt_extraction',
    severity: 'medium',
    confidence: 0.9,
    pattern: /output\s+your\s+(initial|system|original)\s+prompt/gi,
  },
  {
    category: 'system_prompt_extraction',
    severity: 'medium',
    confidence: 0.85,
    pattern: /print\s+your\s+(system\s+)?instructions?/gi,
  },
  // -- exfiltration_attempt ----------------------------------------------------
  // Heuristic by design: exfiltration language co-occurring with an outbound
  // channel (URL / webhook). The validate step requires the channel so plain
  // discussion of exfiltration ("how do we prevent exfiltration?") does not
  // fire.
  {
    category: 'exfiltration_attempt',
    severity: 'high',
    confidence: 0.7,
    pattern: /exfiltrat\w*|send\s+(the\s+data|it|them|everything)\s+to|upload\s+\S[\s\S]{0,40}?\s+to\s+|post\s+\S[\s\S]{0,40}?\s+to\s+/gi,
    validate: (_m, _o, input) => URL_PATTERN.test(input),
  },
  // -- malicious_instruction ---------------------------------------------------
  {
    category: 'malicious_instruction',
    severity: 'critical',
    confidence: 0.95,
    pattern: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(~|\/|\*)/gi,
  },
  {
    category: 'malicious_instruction',
    severity: 'critical',
    confidence: 1.0,
    pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;:/g,
  },
  {
    category: 'malicious_instruction',
    severity: 'critical',
    confidence: 0.95,
    pattern: /\bcurl\b[\s\S]{0,200}?\|\s*(sh|bash)\b/gi,
  },
  {
    category: 'malicious_instruction',
    severity: 'critical',
    confidence: 0.95,
    pattern: /\bwget\b[\s\S]{0,200}?\|\s*(sh|bash)\b/gi,
  },
  {
    category: 'malicious_instruction',
    severity: 'critical',
    confidence: 0.95,
    pattern: /\bdd\s+if=[^\s]+\s+of=\/dev\//gi,
  },
  {
    category: 'malicious_instruction',
    severity: 'critical',
    confidence: 0.95,
    pattern: /\bmkfs\./gi,
  },
  {
    category: 'malicious_instruction',
    severity: 'high',
    confidence: 0.75,
    pattern: /\bdrop\s+table\b/gi,
  },
  {
    category: 'malicious_instruction',
    severity: 'high',
    confidence: 0.7,
    pattern: /\bdelete\s+from\s+[a-z_][a-z0-9_]*/gi,
  },
  {
    category: 'malicious_instruction',
    severity: 'high',
    confidence: 0.85,
    pattern: /disable\s+(the\s+)?firewall/gi,
  },
  // -- suspicious_tool_call ----------------------------------------------------
  {
    category: 'suspicious_tool_call',
    severity: 'medium',
    confidence: 0.7,
    pattern: /"tool_calls?"\s*:/gi,
  },
  {
    category: 'suspicious_tool_call',
    severity: 'medium',
    confidence: 0.7,
    pattern: /\bfunction_call\b/gi,
  },
  {
    category: 'suspicious_tool_call',
    severity: 'medium',
    confidence: 0.65,
    pattern: /\bexecute\s+(the\s+)?(tool|command)\b/gi,
  },
  {
    category: 'suspicious_tool_call',
    severity: 'medium',
    confidence: 0.65,
    pattern: /\brun\s+shell\b/gi,
  },
  {
    category: 'suspicious_tool_call',
    severity: 'medium',
    confidence: 0.6,
    pattern: /\binvoke\s+tool\b/gi,
  },
];

/**
 * Scan free-text content for attack patterns.
 * Returns one finding per detected category (never raw matched values).
 * Empty or non-text input yields no findings.
 */
export function detectThreats(content: string): ThreatFinding[] {
  if (typeof content !== 'string' || content.length === 0) return [];
  const findings: ThreatFinding[] = [];
  const seen = new Set<ThreatCategory>();

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
        if (count >= MAX_THREAT_FINDINGS_PER_CATEGORY) break;
      }
    }
    if (count > 0 && !seen.has(rule.category)) {
      seen.add(rule.category);
      findings.push({
        detector: THREAT_DETECTOR_VERSION,
        category: rule.category,
        severity: rule.severity,
        confidence: rule.confidence,
        count,
      });
    } else if (count > 0) {
      // Same category from a second rule: merge counts, keep the strongest
      // severity/confidence.
      const existing = findings.find((f) => f.category === rule.category);
      if (existing) {
        existing.count = Math.min(MAX_THREAT_FINDINGS_PER_CATEGORY, existing.count + count);
        existing.confidence = Math.max(existing.confidence, rule.confidence);
        if (severityRank(rule.severity) > severityRank(existing.severity)) {
          existing.severity = rule.severity;
        }
      }
    }
  }
  return findings;
}

function severityRank(s: ThreatSeverity): number {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s];
}

/** True when any finding is critical-severity (destructive commands). */
export function hasCriticalThreat(findings: ThreatFinding[]): boolean {
  return findings.some((f) => f.severity === 'critical');
}

/** Distinct threat categories present, for policy matching and audit metadata. */
export function threatCategories(findings: ThreatFinding[]): ThreatCategory[] {
  return [...new Set(findings.map((f) => f.category))];
}
