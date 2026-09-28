// RAG helpers — Phase E (RAG security).
//
// Zero-dependency shared module (works in Deno edge functions and the
// Node-based verification scripts). Pure functions only:
//   - deterministic text chunking with overlap
//   - cosine similarity + ranking over a pre-filtered candidate set
//   - clearance/role mirrors of the SQL maps in 028_rag_security.sql
//   - OpenAI-compatible embedding calls (provider key stays server-side)
//
// Security contract: similarity ranking NEVER sees unfiltered rows. The SQL
// RPC `rag_search_candidates` applies the tenant/clearance/grant filter
// first; rankBySimilarity only orders what the filter returned. Chunks with
// missing or dimension-mismatched embeddings are excluded, never guessed.

export const RAG_VERSION = 'rag-v1';

export const CLEARANCE_ORDER = ['public', 'internal', 'confidential', 'restricted'] as const;
export type Clearance = (typeof CLEARANCE_ORDER)[number];

/** Mirror of public.rag_clearance_rank. Returns -1 for unknown levels. */
export function clearanceRank(level: string): number {
  const i = (CLEARANCE_ORDER as readonly string[]).indexOf(level);
  return i === -1 ? -1 : i;
}

/** Mirror of public.rag_role_max_clearance. */
export function roleMaxClearance(role: string): Clearance {
  switch (role) {
    case 'owner':
    case 'admin':
    case 'security':
      return 'restricted';
    case 'developer':
      return 'confidential';
    case 'analyst':
      return 'internal';
    default:
      return 'public';
  }
}

export interface ChunkOptions {
  /** Target maximum chunk size in characters. Default 1000. */
  maxChars?: number;
  /** Overlap carried from the previous chunk. Default 200. */
  overlapChars?: number;
}

function overlapTail(s: string, n: number): string {
  if (n <= 0 || !s) return '';
  const tail = s.slice(-n);
  const sp = tail.indexOf(' ');
  return sp === -1 ? tail : tail.slice(sp + 1);
}

/**
 * Deterministically split text into chunks of at most maxChars characters.
 * Splits on paragraph breaks, then sentences, then hard-splits long runs.
 * Each chunk (after the first) starts with up to overlapChars of the
 * previous chunk's tail so split concepts stay retrievable. Chunks never
 * exceed maxChars; when a piece alone is near maxChars the overlap is
 * dropped for that boundary rather than overflowing.
 */
export function chunkText(text: string, opts: ChunkOptions = {}): string[] {
  const maxChars = Math.max(64, Math.floor(opts.maxChars ?? 1000));
  const overlapChars = Math.max(0, Math.min(Math.floor(opts.overlapChars ?? 200), Math.floor(maxChars / 2)));

  // 1. Atomic pieces: paragraphs -> sentences -> hard splits.
  const pieces: string[] = [];
  for (const para of text.split(/\n\s*\n/)) {
    const p = para.replace(/\s+/g, ' ').trim();
    if (!p) continue;
    if (p.length <= maxChars) {
      pieces.push(p);
      continue;
    }
    for (const s of p.split(/(?<=[.!?])\s+/)) {
      const t = s.trim();
      if (!t) continue;
      if (t.length <= maxChars) {
        pieces.push(t);
        continue;
      }
      for (let i = 0; i < t.length; i += maxChars) {
        const hard = t.slice(i, i + maxChars).trim();
        if (hard) pieces.push(hard);
      }
    }
  }
  if (pieces.length === 0) return [];

  // 2. Greedy pack with overlap carry.
  const chunks: string[] = [];
  let cur = '';
  for (const piece of pieces) {
    const add = cur ? ' ' + piece : piece;
    if (cur.length + add.length <= maxChars) {
      cur += add;
      continue;
    }
    if (cur) chunks.push(cur);
    const carry = overlapTail(cur, overlapChars);
    cur = carry && carry.length + 1 + piece.length <= maxChars ? carry + ' ' + piece : piece;
  }
  if (cur) chunks.push(cur);
  return chunks;
}

/** Cosine similarity in [-1, 1]; 0 when inputs are unusable (never NaN). */
export function cosineSimilarity(a: ArrayLike<number>, b: ArrayLike<number>): number {
  if (!a || !b || a.length === 0 || a.length !== b.length) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    if (!Number.isFinite(x) || !Number.isFinite(y)) return 0;
    dot += x * y;
    na += x * x;
    nb += y * y;
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

export interface RankCandidate {
  id: string;
  embedding: ArrayLike<number> | null | undefined;
  [key: string]: unknown;
}

export interface RankedResult<T> {
  candidate: T;
  score: number;
}

/**
 * Rank pre-filtered candidates by cosine similarity to the query embedding.
 * Candidates with missing or dimension-mismatched embeddings are excluded.
 * Callers MUST pass only rows returned by rag_search_candidates (or an
 * equally filtered set) — this function ranks, it does not authorize.
 */
export function rankBySimilarity<T extends RankCandidate>(
  queryEmbedding: ArrayLike<number>,
  candidates: T[],
  topK: number,
): RankedResult<T>[] {
  const k = Math.max(1, Math.min(Math.floor(topK) || 1, 50));
  return candidates
    .filter((c) => c.embedding != null && c.embedding.length === queryEmbedding.length && queryEmbedding.length > 0)
    .map((c) => ({ candidate: c, score: cosineSimilarity(queryEmbedding, c.embedding as ArrayLike<number>) }))
    .sort((x, y) => y.score - x.score)
    .slice(0, k);
}

export interface EmbedConfig {
  /** Base URL, e.g. https://api.openai.com/v1 (already SSRF-checked by caller). */
  baseUrl: string;
  apiKey: string;
  model: string;
}

interface EmbeddingData {
  embedding: number[];
  index: number;
}

/**
 * OpenAI-compatible embeddings call (also serves OpenAI-compatible custom
 * providers). Batches inputs; returns embeddings in input order. Throws on
 * provider errors — callers map to 502 without leaking key material.
 */
export async function embedTexts(
  cfg: EmbedConfig,
  texts: string[],
  fetchImpl: typeof fetch = fetch,
  timeoutMs = 60_000,
): Promise<number[][]> {
  if (!cfg.model) throw new Error('embedding_model is required');
  const base = cfg.baseUrl.replace(/\/$/, '');
  const out: number[][] = new Array(texts.length);
  const BATCH = 64;
  for (let start = 0; start < texts.length; start += BATCH) {
    const batch = texts.slice(start, start + BATCH);
    const res = await fetchImpl(`${base}/embeddings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${cfg.apiKey}`,
      },
      body: JSON.stringify({ model: cfg.model, input: batch }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Embedding provider returned ${res.status}.`);
    const data = (await res.json()) as { data?: EmbeddingData[] };
    const rows = Array.isArray(data.data) ? [...data.data].sort((a, b) => a.index - b.index) : [];
    if (rows.length !== batch.length) throw new Error('Embedding provider returned a mismatched batch.');
    for (const row of rows) {
      if (!Array.isArray(row.embedding) || row.embedding.length === 0) {
        throw new Error('Embedding provider returned an empty embedding.');
      }
      out[start + row.index] = row.embedding;
    }
  }
  return out;
}
