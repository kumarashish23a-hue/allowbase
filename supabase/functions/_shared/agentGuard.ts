// agentGuard.ts — agent guardrails (agent-v1)
//
// Pure, dependency-free helpers for the Phase G agent guardrail system.
// The authoritative enforcement lives in SQL
// (public.check_agent_guardrails); this module holds what the edge
// functions need client-side:
//
//   - canonicalize / hashArguments: deterministic SHA-256 of tool
//     arguments (key order independent), used for loop detection.
//   - trailingIdenticalRun: pure trailing-run counter mirroring the SQL
//     loop-detection semantics.
//   - parseGuardVerdict: shape-check the SQL function's jsonb verdict.
//
// No network, no env, no imports — Deno and Node (tests) safe.
// crypto.subtle is available in Deno and in Node 18+.

export const AGENT_GUARD_VERSION = 'agent-v1' as const;

export type GuardDecision = 'allow' | 'require_approval' | 'block';

export interface GuardVerdict {
  decision: GuardDecision;
  forceApproval: boolean;
  reasons: string[];
  escalation: boolean;
}

/** Deterministic JSON: object keys sorted recursively, arrays ordered. */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (typeof value === 'object') {
    const rec = value as Record<string, unknown>;
    const keys = Object.keys(rec).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(rec[k])).join(',') + '}';
  }
  const s = JSON.stringify(value);
  return typeof s === 'string' ? s : 'null';
}

/** SHA-256 hex of the canonicalized arguments. */
export async function hashArguments(args: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalize(args ?? {}));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** A recorded tool call for loop analysis (most-recent first). */
export interface RecentCall {
  toolName: string;
  argsHash: string;
}

/**
 * Count the trailing run of identical (tool, args hash) calls.
 * Mirrors the SQL loop detector: the NEXT identical call is the
 * (run + 1)-th in a row; the SQL blocks when run >= the agent's
 * max_consecutive_identical_calls threshold.
 */
export function trailingIdenticalRun(
  recent: RecentCall[],
  toolName: string,
  argsHash: string,
): number {
  let run = 0;
  for (const call of recent) {
    if (call.toolName === toolName && call.argsHash === argsHash) run++;
    else break;
  }
  return run;
}

/**
 * Shape-check and normalize the jsonb verdict returned by
 * public.check_agent_guardrails. Throws on malformed input.
 */
export function parseGuardVerdict(raw: unknown): GuardVerdict {
  if (!raw || typeof raw !== 'object') throw new Error('guard verdict must be an object');
  const v = raw as Record<string, unknown>;
  if (v.decision !== 'allow' && v.decision !== 'require_approval' && v.decision !== 'block') {
    throw new Error('guard verdict has invalid decision');
  }
  const reasons = Array.isArray(v.reasons) ? v.reasons.filter((r): r is string => typeof r === 'string') : [];
  return {
    decision: v.decision,
    forceApproval: v.force_approval === true,
    reasons,
    escalation: v.escalation === true,
  };
}

/**
 * Whether the guardrail decision forces a require_approval outcome on a
 * pipeline that would otherwise allow the call.
 */
export function guardForcesApproval(verdict: GuardVerdict): boolean {
  return verdict.decision === 'allow' && verdict.forceApproval;
}
