/**
 * Deterministic plain-English rule parser for the policy builder.
 *
 * Turns a sentence like "block emails and phone numbers sent to external AI"
 * into the exact condition vocabulary the enforcement engine understands
 * (see FIELDS in PolicyModals.tsx). No LLM, no network — the parse is fully
 * deterministic so every policy stays explainable and auditable.
 */
import type {
  PolicyAction,
  PolicyConditionDraft,
  PolicyOperator,
} from '../services/policyService';

export interface ParsedCondition extends PolicyConditionDraft {
  /** Human-readable chip text, e.g. "finds emails or phone numbers". */
  label: string;
}

export interface ParsedRule {
  action: PolicyAction;
  /** 'found' when the sentence named an action, 'default' when we fell back to block. */
  actionSource: 'found' | 'default';
  conditions: ParsedCondition[];
  warnings: string[];
}

/** action keyword → action, checked by earliest occurrence in the text. */
const ACTION_KEYWORDS: { action: PolicyAction; pattern: RegExp }[] = [
  { action: 'block', pattern: /\b(block|stop|stops|prevent|forbid|deny|denies|never allow|no access)\b/ },
  { action: 'require_approval', pattern: /\b(ask me|approval|approve|review|hold|holds|confirm|permission)\b/ },
  { action: 'redact', pattern: /\b(redact|remove|removes|strip|delete)\b/ },
  { action: 'mask', pattern: /\b(mask|hide|hides|cover|covers|obscure|anonymize)\b/ },
  { action: 'allow', pattern: /\b(allow|allows|permit|let through|let it through)\b/ },
];

/** content.category value → synonyms. */
const CONTENT_SYNONYMS: { value: string; pattern: RegExp; label: string }[] = [
  { value: 'email', pattern: /\b(e-?mails?)\b/, label: 'emails' },
  { value: 'phone', pattern: /\b(phones?|phone numbers?|mobiles?|mobile numbers?|telephone)\b/, label: 'phone numbers' },
  { value: 'credit_card', pattern: /\b(credit cards?|card numbers?|debit cards?|cc numbers?)\b/, label: 'credit cards' },
  { value: 'gov_id', pattern: /\b(ssns?|social security( numbers?)?|national ids?|passports?|driver'?s licen[sc]es?)\b/, label: 'government IDs' },
  { value: 'api_key', pattern: /\b(api keys?|access keys?|secret keys?)\b/, label: 'API keys' },
  { value: 'private_key', pattern: /\b(private keys?|ssh keys?)\b/, label: 'private keys' },
  { value: 'jwt', pattern: /\b(jwts?|auth tokens?|bearer tokens?|tokens?)\b/, label: 'tokens' },
  { value: 'secret', pattern: /\b(secrets?|passwords?|credentials?)\b/, label: 'secrets' },
];

/** data.classification value → synonyms. */
const CLASS_SYNONYMS: { value: string; pattern: RegExp; label: string }[] = [
  { value: 'public', pattern: /\bpublic\b/, label: 'public' },
  { value: 'internal', pattern: /\binternal\b/, label: 'internal' },
  { value: 'confidential', pattern: /\b(confidential|private|confidentially)\b/, label: 'confidential' },
  { value: 'restricted', pattern: /\b(restricted|top[- ]secret|highly confidential)\b/, label: 'restricted' },
];

const SENSITIVITY_PATTERN = /\b(critical|high|medium|low)\s+sensitivity\b|\bsensitivity\s+(is\s+)?(critical|high|medium|low)\b/;
const EXTERNAL_PATTERN = /\b(external ai|outside( the| our)? (company|org|organization)|third[- ]party|public ai|any ai|untrusted)\b/;

/** ai.provider value → synonyms. */
const PROVIDER_SYNONYMS: { value: string; pattern: RegExp; label: string }[] = [
  { value: 'openai', pattern: /\b(chatgpt|openai|\bgpt\b)/, label: 'OpenAI' },
  { value: 'anthropic', pattern: /\b(claude|anthropic)\b/, label: 'Anthropic' },
  { value: 'google', pattern: /\b(gemini|google)\b/, label: 'Google' },
  { value: 'azure', pattern: /\bazure\b/, label: 'Azure' },
  { value: 'internal', pattern: /\b(internal ai|our own ai)\b/, label: 'internal AI' },
];

const NEGATION_PATTERN = /\bexcept\b|\bunless\b|\bnot\b|don't|never/;

interface Clause {
  text: string;
  negated: boolean;
}

function splitClauses(text: string): Clause[] {
  // Split the sentence at except/unless: everything after the split is negated.
  const clauses: Clause[] = [];
  text.split(/\bexcept\b|\bunless\b/).forEach((segment, segIndex) => {
    const forcedNeg = segIndex > 0;
    for (const part of segment.split(/[,;]|\band\b|\bbut\b/)) {
      const t = part.trim();
      if (!t) continue;
      clauses.push({ text: t, negated: forcedNeg || NEGATION_PATTERN.test(t) });
    }
  });
  return clauses;
}

function detectAction(text: string): { action: PolicyAction; source: 'found' | 'default' } {
  let best: { action: PolicyAction; index: number } | null = null;
  for (const { action, pattern } of ACTION_KEYWORDS) {
    const m = pattern.exec(text);
    if (m && (best === null || m.index < best.index)) {
      best = { action, index: m.index };
    }
  }
  if (best) return { action: best.action, source: 'found' };
  return { action: 'block', source: 'default' };
}

function joinLabels(labels: string[]): string {
  if (labels.length === 1) return labels[0];
  return `${labels.slice(0, -1).join(', ')} or ${labels[labels.length - 1]}`;
}

/** Parse a plain-English rule sentence into engine-ready conditions. */
export function parseRuleSentence(input: string): ParsedRule {
  const warnings: string[] = [];
  const text = input.toLowerCase().replace(/\s+/g, ' ').trim();
  const { action, source } = detectAction(text);
  if (source === 'default') {
    warnings.push('No action named — defaulting to Block. Say “ask me” or “hide” for a gentler rule.');
  }

  const clauses = splitClauses(text);

  // Collect matches per field, split by polarity.
  const contentPos = new Map<string, string>();
  const contentNeg = new Map<string, string>();
  const classPos = new Map<string, string>();
  const classNeg = new Map<string, string>();
  const providerPos = new Map<string, string>();
  const providerNeg = new Map<string, string>();
  let sensitivity: { value: string; negated: boolean } | null = null;
  let external: { value: boolean; negated: boolean } | null = null;

  for (const clause of clauses) {
    const target = (m: Map<string, string>, n: Map<string, string>) => (clause.negated ? n : m);
    for (const s of CONTENT_SYNONYMS) {
      if (s.pattern.test(clause.text)) target(contentPos, contentNeg).set(s.value, s.label);
    }
    for (const s of CLASS_SYNONYMS) {
      if (s.pattern.test(clause.text)) target(classPos, classNeg).set(s.value, s.label);
    }
    for (const s of PROVIDER_SYNONYMS) {
      if (s.pattern.test(clause.text)) target(providerPos, providerNeg).set(s.value, s.label);
    }
    const sm = SENSITIVITY_PATTERN.exec(clause.text);
    if (sm) {
      const v = (sm[1] ?? sm[3] ?? '').toLowerCase();
      if (['critical', 'high', 'medium', 'low'].includes(v)) {
        sensitivity = { value: v, negated: clause.negated };
      }
    }
    if (EXTERNAL_PATTERN.test(clause.text)) {
      external = { value: true, negated: clause.negated };
    }
  }

  const conditions: ParsedCondition[] = [];

  const multi = (
    field: string,
    pos: Map<string, string>,
    neg: Map<string, string>,
    describe: (labels: string[]) => string,
  ) => {
    if (pos.size > 0) {
      const values = [...pos.keys()];
      conditions.push({
        field,
        operator: 'in',
        value: values,
        label: describe([...pos.values()]),
      });
    }
    if (neg.size > 0) {
      const values = [...neg.keys()];
      conditions.push({
        field,
        operator: 'not_in' as PolicyOperator,
        value: values,
        label: `not ${describe([...neg.values()])}`,
      });
    }
  };

  multi('content.category', contentPos, contentNeg, (l) => `finds ${joinLabels(l)}`);
  multi('data.classification', classPos, classNeg, (l) => `data is ${joinLabels(l)}`);
  multi('ai.provider', providerPos, providerNeg, (l) => `AI is ${joinLabels(l)}`);
  if (sensitivity) {
    conditions.push({
      field: 'data.sensitivity_level',
      operator: sensitivity.negated ? 'not_equals' : 'equals',
      value: [sensitivity.value],
      label: `sensitivity is ${sensitivity.value}`,
    });
  }
  if (external) {
    const val = external.negated ? false : external.value;
    conditions.push({
      field: 'ai.is_external',
      operator: 'equals',
      value: val,
      label: val ? 'AI is external' : 'AI is internal',
    });
  }

  if (conditions.length === 0) {
    warnings.push(
      'Couldn’t find anything to guard. Mention what to protect — emails, secrets, confidential data — and what to do: block, ask me, or hide.',
    );
  }

  return { action, actionSource: source, conditions, warnings };
}

const ACTION_VERBS: Record<PolicyAction, string> = {
  block: 'Block',
  require_approval: 'Ask before allowing',
  mask: 'Hide secrets in',
  redact: 'Redact',
  allow: 'Allow',
};

/** One-line summary of the parsed rule, e.g. "IF finds emails AND AI is external THEN block". */
export function summarizeParsed(rule: ParsedRule): string {
  if (rule.conditions.length === 0) return '';
  const ifPart = rule.conditions.map((c) => c.label).join(' AND ');
  const thenVerb =
    rule.action === 'block'
      ? 'stop it — the AI never sees it'
      : rule.action === 'require_approval'
        ? 'hold it until someone approves'
        : rule.action === 'mask'
          ? 'hide the secrets, then allow it'
          : rule.action === 'redact'
            ? 'remove the sensitive parts, then allow it'
            : 'let it through, logged';
  return `If ${ifPart}, ${thenVerb}.`;
}

/** Suggest a policy name from the parsed rule. */
export function suggestPolicyName(rule: ParsedRule): string {
  if (rule.conditions.length === 0) return '';
  const bits = rule.conditions.map((c) => c.label);
  const name = `${ACTION_VERBS[rule.action]} — ${bits.join(', ')}`;
  return name.length > 80 ? `${name.slice(0, 77)}…` : name;
}
