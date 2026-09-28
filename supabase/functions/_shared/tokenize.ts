// Shared tokenization-vault helpers (Deno Edge Functions + Node tests).
//
// Reversible alternative to masking: sensitive spans are replaced with opaque
// token ids (`abt_tok_<random>`) before content leaves for an AI provider.
// The original values are AES-GCM encrypted with TOKEN_ENCRYPTION_KEY and
// stored in the privacy_tokens table; detokenization restores them only for
// the same organization, only while the token is unexpired and unrevoked.
//
// Security properties:
// - Token ids are 128-bit random (unguessable); the vault is looked up by id.
// - Plaintext values never leave this module except into the caller's string.
//   Findings, logs, and audit rows carry categories and counts, never values.
// - Same-organization enforcement happens here AND in the lookup: a token
//   created for org A never resolves for org B.
//
// Zero dependencies: WebCrypto for AES-GCM and randomness, and a
// caller-supplied vault interface so unit tests can use an in-memory fake.

import { detectSensitiveSpans } from './detect.ts';
import type { DetectionCategory } from './detect.ts';

/** Token id format: abt_tok_<22 base64url chars> (128-bit random). */
export const TOKEN_ID_PREFIX = 'abt_tok_';
export const TOKEN_ID_PATTERN = /^abt_tok_[A-Za-z0-9_-]{22}$/;
/** Matches token ids embedded in larger text (for detokenization). */
const TOKEN_ID_SCAN = /abt_tok_[A-Za-z0-9_-]{22}/g;

/** A row in the privacy_tokens table (plaintext never included). */
export interface StoredToken {
  token_id: string;
  organization_id: string;
  value_encrypted: string;
  value_iv: string;
  purpose: string;
  expires_at: string;
  revoked_at: string | null;
}

/** Minimal vault interface the edge function implements with Supabase. */
export interface TokenVault {
  create(entry: {
    organization_id: string;
    token_id: string;
    value_encrypted: string;
    value_iv: string;
    purpose: string;
    created_by: string | null;
    expires_at: string;
  }): Promise<void>;
  lookup(token_id: string): Promise<StoredToken | null>;
  recordResolve(token_id: string): Promise<void>;
  audit(entry: {
    organization_id: string;
    actor_user_id: string | null;
    actor_type: string;
    action: string;
    resource_type: string;
    resource_id: string;
    result: string;
    metadata: Record<string, unknown>;
  }): Promise<void>;
}

export interface TokenizeContext {
  vault: TokenVault;
  organizationId: string;
  /** 64 hex chars, from the TOKEN_ENCRYPTION_KEY secret. */
  encryptionKeyHex: string;
  actorUserId?: string | null;
  actorType?: string;
  /** Token lifetime; defaults to 7 days. */
  expiresInHours?: number;
  /** Override for tests. */
  now?: () => number;
}

export interface TokenizeResult {
  text: string;
  tokens: Array<{ tokenId: string; category: DetectionCategory }>;
}

export interface DetokenizeResult {
  text: string;
  resolved: number;
  unresolved: number;
}

function base64Encode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  // btoa exists in Deno and browsers; Node 16+ exposes it globally too.
  return btoa(binary);
}

function base64Decode(s: string): Uint8Array {
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function importVaultKey(keyHex: string): Promise<CryptoKey> {
  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error(
      'TOKEN_ENCRYPTION_KEY is not configured. Set it with: supabase secrets set TOKEN_ENCRYPTION_KEY=$(openssl rand -hex 32)',
    );
  }
  const raw = new Uint8Array(32);
  for (let i = 0; i < 32; i++) raw[i] = parseInt(keyHex.slice(i * 2, i * 2 + 2), 16);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Generate an unguessable token id. Exported for tests. */
export function generateTokenId(randomBytes?: (n: number) => Uint8Array): string {
  const bytes = randomBytes
    ? randomBytes(16)
    : crypto.getRandomValues(new Uint8Array(16));
  return TOKEN_ID_PREFIX + base64UrlEncode(bytes);
}

async function encryptValue(plaintext: string, keyHex: string): Promise<{ ciphertext: string; iv: string }> {
  const key = await importVaultKey(keyHex);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  return { ciphertext: base64Encode(new Uint8Array(ct)), iv: base64Encode(iv) };
}

async function decryptValue(ciphertext: string, iv: string, keyHex: string): Promise<string> {
  const key = await importVaultKey(keyHex);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64Decode(iv) },
    key,
    base64Decode(ciphertext),
  );
  return new TextDecoder().decode(pt);
}

/**
 * Replace sensitive spans with vault token ids.
 *
 * Only spans whose category appears in `findings` are tokenized, so the
 * policy's scope (e.g. "tokenize emails") is honored. Each distinct span
 * gets its own token id; repeated identical values get distinct tokens so
 * frequency analysis on the provider side reveals nothing.
 */
export async function tokenize(
  text: string,
  findings: Array<{ category: string }>,
  ctx: TokenizeContext,
): Promise<TokenizeResult> {
  if (typeof text !== 'string' || text.length === 0) return { text, tokens: [] };
  const wanted = new Set(findings.map((f) => f.category));
  const spans = detectSensitiveSpans(text).filter((s) => wanted.has(s.category));
  if (spans.length === 0) return { text, tokens: [] };

  const nowMs = ctx.now ? ctx.now() : Date.now();
  const expiresAt = new Date(nowMs + (ctx.expiresInHours ?? 24 * 7) * 3600 * 1000).toISOString();

  // Replace from the end so earlier offsets stay valid.
  const ordered = [...spans].sort((a, b) => b.start - a.start);
  let out = text;
  const tokens: TokenizeResult['tokens'] = [];
  for (const span of ordered) {
    const value = text.slice(span.start, span.end);
    const tokenId = generateTokenId();
    const { ciphertext, iv } = await encryptValue(value, ctx.encryptionKeyHex);
    await ctx.vault.create({
      organization_id: ctx.organizationId,
      token_id: tokenId,
      value_encrypted: ciphertext,
      value_iv: iv,
      purpose: 'pii_tokenization',
      created_by: ctx.actorUserId ?? null,
      expires_at: expiresAt,
    });
    await ctx.vault.audit({
      organization_id: ctx.organizationId,
      actor_user_id: ctx.actorUserId ?? null,
      actor_type: ctx.actorType ?? 'system',
      action: 'token_created',
      resource_type: 'privacy_token',
      resource_id: tokenId,
      result: 'ok',
      // Category only — never the value.
      metadata: { category: span.category },
    });
    out = out.slice(0, span.start) + tokenId + out.slice(span.end);
    tokens.push({ tokenId, category: span.category });
  }
  return { text: out, tokens };
}

/**
 * Restore token ids to their original values.
 *
 * Resolves only for the calling organization; expired, revoked, unknown, or
 * foreign-org tokens are left in place (opaque to the caller) and counted
 * as unresolved. Every successful resolve writes an audit row.
 */
export async function detokenize(text: string, ctx: TokenizeContext): Promise<DetokenizeResult> {
  if (typeof text !== 'string' || text.length === 0) return { text, resolved: 0, unresolved: 0 };
  const ids = [...new Set(text.match(TOKEN_ID_SCAN) ?? [])];
  if (ids.length === 0) return { text, resolved: 0, unresolved: 0 };

  const nowMs = ctx.now ? ctx.now() : Date.now();
  let out = text;
  let resolved = 0;
  let unresolved = 0;
  for (const tokenId of ids) {
    let stored: StoredToken | null = null;
    try {
      stored = await ctx.vault.lookup(tokenId);
    } catch {
      stored = null;
    }
    const usable =
      stored !== null &&
      stored.organization_id === ctx.organizationId &&
      stored.revoked_at === null &&
      Date.parse(stored.expires_at) > nowMs;
    if (!usable || !stored) {
      unresolved++;
      continue;
    }
    let value: string;
    try {
      value = await decryptValue(stored.value_encrypted, stored.value_iv, ctx.encryptionKeyHex);
    } catch {
      unresolved++;
      continue;
    }
    out = out.split(tokenId).join(value);
    resolved++;
    try {
      await ctx.vault.recordResolve(tokenId);
    } catch {
      // Resolve already succeeded; a bookkeeping failure must not break it.
    }
    await ctx.vault.audit({
      organization_id: ctx.organizationId,
      actor_user_id: ctx.actorUserId ?? null,
      actor_type: ctx.actorType ?? 'system',
      action: 'token_resolved',
      resource_type: 'privacy_token',
      resource_id: tokenId,
      result: 'ok',
      // Category is not stored on resolve path; purpose only. Never the value.
      metadata: { purpose: stored.purpose },
    });
  }
  return { text: out, resolved, unresolved };
}
