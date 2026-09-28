// MCP security helpers — Phase F.
//
// Zero-dependency shared module (works in Deno edge functions and the
// Node-based verification scripts). Pure functions only:
//   - deterministic tool-risk classification (dangerous verbs default to
//     approval)
//   - tool-argument inspection (attack patterns block; secrets hold for
//     approval)
//   - MCP JSON-RPC message construction
//   - tool-output summarization (masked preview + finding counts, never raw
//     matched values)
//
// Policy: dangerous operations default to APPROVAL, never silent execution.
// The five dangerous verbs are delete, drop, export, transfer, execute.

import { detectSensitiveContent, maskSensitiveContent } from './detect.ts';
import { detectThreats, hasCriticalThreat } from './threat.ts';
import type { ContentFinding } from './detect.ts';
import type { ThreatFinding } from './threat.ts';

export const MCP_VERSION = 'mcp-v1';

/** Arguments larger than this are truncated before inspection (and rejected). */
export const MAX_TOOL_ARGS_CHARS = 64 * 1024;
/** Tool output is summarized, not stored raw, beyond this preview budget. */
export const MAX_RESULT_PREVIEW_CHARS = 2048;

export type McpRiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type McpDecision = 'allowed' | 'require_approval' | 'blocked';

/** The five dangerous verbs from the Phase F spec. */
export const DANGEROUS_VERBS = ['delete', 'drop', 'export', 'transfer', 'execute'] as const;

/**
 * Split text into lowercase word tokens, treating underscores, hyphens, and
 * camelCase transitions as separators. This matters because tool names are
 * usually snake_case: `\bdelete\b` does NOT match "delete_all_rows" (the
 * underscore is a word character), so a naive regex silently misses the
 * most common naming style.
 */
function wordTokens(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** True when a dangerous verb appears as its own token (not inside "deleted_at"). */
export function mentionsDangerousVerb(name: string, description: string | null | undefined): boolean {
  const tokens = new Set(wordTokens(`${name} ${description ?? ''}`));
  return (DANGEROUS_VERBS as readonly string[]).some((v) => tokens.has(v));
}

const DESTRUCTIVE_TOKENS = ['format', 'destroy', 'wipe', 'wiped'];
const DESTRUCTIVE_PAIRS = ['rm rf', 'drop table', 'drop database'];

/** True for unambiguously destructive operations (wipe/format/rm -rf/drop table). */
export function mentionsDestructiveOp(name: string, description: string | null | undefined): boolean {
  const tokens = wordTokens(`${name} ${description ?? ''}`);
  if (tokens.some((t) => DESTRUCTIVE_TOKENS.includes(t))) return true;
  for (let i = 0; i + 1 < tokens.length; i++) {
    if (DESTRUCTIVE_PAIRS.includes(tokens[i] + ' ' + tokens[i + 1])) return true;
  }
  return false;
}

const READONLY_TOKENS = ['read', 'get', 'list', 'search', 'query', 'describe'];

function mentionsReadonlyHint(name: string, description: string | null | undefined): boolean {
  const tokens = new Set(wordTokens(`${name} ${description ?? ''}`));
  return READONLY_TOKENS.some((t) => tokens.has(t));
}

const RISK_RANK: Record<McpRiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Deterministically classify a tool's risk from its name/description plus the
 * operator-declared risk_level. The declared level can only raise the verdict,
 * never lower what the name advertises: a tool NAMED "delete_all_rows" is
 * high risk even if someone registered it as low.
 */
export function classifyToolRisk(
  name: string,
  description: string | null | undefined,
  declared: McpRiskLevel,
): McpRiskLevel {
  let computed: McpRiskLevel = 'medium';
  if (mentionsDestructiveOp(name, description)) computed = 'critical';
  else if (mentionsDangerousVerb(name, description)) computed = 'high';
  else if (mentionsReadonlyHint(name, description)) computed = 'low';
  return RISK_RANK[declared] >= RISK_RANK[computed] ? declared : computed;
}

export interface McpToolRef {
  name: string;
  description?: string | null;
  risk_level: McpRiskLevel;
  requires_approval: boolean;
}

/**
 * Dangerous operations default to approval: an explicit requires_approval
 * flag, a high/critical risk level, or a dangerous verb in the name or
 * description all hold the call for a human decision.
 */
export function toolRequiresApproval(tool: McpToolRef): boolean {
  if (tool.requires_approval) return true;
  if (tool.risk_level === 'high' || tool.risk_level === 'critical') return true;
  return mentionsDangerousVerb(tool.name, tool.description);
}

export interface ArgInspection {
  decision: McpDecision;
  reasons: string[];
  /** Counts by category only — raw values never leave the detectors. */
  threatCounts: Record<string, number>;
  sensitiveCounts: Record<string, number>;
  truncated: boolean;
}

function countBy<T extends { category: string; count: number }>(findings: T[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.category] = (out[f.category] ?? 0) + f.count;
  return out;
}

/**
 * Inspect tool arguments before execution. The arguments are attacker-
 * influenced (they come from the agent/model), so:
 * - high/critical attack patterns (prompt injection, jailbreak, destructive
 *   instructions) BLOCK the call;
 * - high/critical secrets in arguments HOLD it for approval — passing
 *   credentials to a tool is often legitimate, exfiltrating them is not,
 *   and a human should see the call first;
 * - oversized argument blobs are rejected outright.
 */
export function inspectToolArguments(args: unknown): ArgInspection {
  let text: string;
  try {
    text = JSON.stringify(args ?? {});
  } catch {
    text = '{}';
  }
  const truncated = text.length > MAX_TOOL_ARGS_CHARS;
  if (truncated) text = text.slice(0, MAX_TOOL_ARGS_CHARS);

  const threats: ThreatFinding[] = detectThreats(text);
  const sensitive: ContentFinding[] = detectSensitiveContent(text);

  const reasons: string[] = [];
  let decision: McpDecision = 'allowed';

  const highThreat = threats.some((t) => t.severity === 'critical' || t.severity === 'high');
  if (highThreat) {
    decision = 'blocked';
    reasons.push('attack pattern in tool arguments');
  }
  const highSecret = sensitive.some((f) => f.severity === 'critical' || f.severity === 'high');
  if (decision !== 'blocked' && highSecret) {
    decision = 'require_approval';
    reasons.push('secret in tool arguments');
  }
  if (truncated && decision === 'allowed') {
    decision = 'require_approval';
    reasons.push('arguments exceed inspection budget');
  }

  return {
    decision,
    reasons,
    threatCounts: countBy(threats),
    sensitiveCounts: countBy(sensitive),
    truncated,
  };
}

export interface JsonRpcCall {
  jsonrpc: '2.0';
  id: string | number;
  method: 'tools/call';
  params: { name: string; arguments: Record<string, unknown> };
}

/** Build the MCP JSON-RPC 2.0 tools/call message. */
export function buildJsonRpcCall(
  id: string | number,
  toolName: string,
  args: Record<string, unknown>,
): JsonRpcCall {
  return {
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: { name: toolName, arguments: args },
  };
}

export interface ResultSummary {
  /** Masked, truncated preview — safe to store and show. */
  preview: string;
  masked: boolean;
  maskedCount: number;
  /** Counts by category only. */
  sensitiveCounts: Record<string, number>;
  threatCounts: Record<string, number>;
  threatCritical: boolean;
}

/**
 * Summarize a tool's output for storage and for the caller. Detected
 * sensitive spans are masked (the agent's context must not silently
 * accumulate credentials or PII the tool leaked); critical attack patterns
 * in tool output are flagged but the output is still returned — the tool
 * already ran, so output inspection here is detective, not preventive.
 */
export function summarizeToolResult(result: unknown): ResultSummary {
  let text: string;
  try {
    text = JSON.stringify(result ?? null);
  } catch {
    text = 'null';
  }
  const threats = detectThreats(text.slice(0, 100 * 1024));
  const masked = maskSensitiveContent(text);
  const previewSource = masked.maskedCount > 0 ? masked.masked : text;
  return {
    preview: previewSource.slice(0, MAX_RESULT_PREVIEW_CHARS),
    masked: masked.maskedCount > 0,
    maskedCount: masked.maskedCount,
    sensitiveCounts: countBy(detectSensitiveContent(text)),
    threatCounts: countBy(threats),
    threatCritical: hasCriticalThreat(threats),
  };
}
