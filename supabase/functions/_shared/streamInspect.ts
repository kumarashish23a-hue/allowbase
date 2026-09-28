// Shared streaming output inspector (Deno Edge Functions + Node tests).
//
// Incrementally scans provider output as it streams, so secrets or attack
// patterns split across chunk boundaries are still caught. A rolling
// overlap buffer (default 2 KB) holds back the tail of the stream: only
// text older than the overlap is emitted, after the window covering it has
// been scanned. This catches a secret whose bytes arrive in two chunks.
//
// Verdicts per step:
// - critical content finding (secrets, private keys, API keys) or critical
//   threat (destructive commands) -> TERMINATE the stream. The offending
//   chunk is dropped, the provider stream is closed, and an audit row is
//   written. This is the response-side blocking Phase A deferred.
// - high-severity content finding (SSN, credit card, ...) -> REDACT: the
//   sensitive spans are masked before the text is emitted.
// - high-severity threat (prompt injection, jailbreak, exfiltration, ...)
//   -> TERMINATE. Attack patterns in model output indicate the model is
//   echoing or complying with an attack; there is no safe partial
//   redaction for them, so the stream stops.
// - medium/low -> pass through; categories and counts are recorded for audit.
//
// Findings NEVER contain raw matched values — only categories, severities,
// and counts — so inspector output is safe to log and store.
//
// Honest residuals (documented, not fixed):
// 1. Termination is not retroactive: bytes already emitted to the caller
//    cannot be pulled back. The overlap only protects the tail.
// 2. An adversarial provider can defeat the overlap by inserting more than
//    STREAM_OVERLAP_BYTES of padding between the halves of a secret: the
//    first half is emitted before the second half arrives. Larger overlap
//    narrows this at the cost of latency; it cannot be closed by buffering
//    alone.
// 3. Encoded exfiltration (base64, homoglyphs, paraphrase) defeats
//    deterministic regex. This inspector is a tripwire, not a proof.
// 4. Token ids (abt_tok_...) match no detection rule and pass through
//    untouched; detokenization is a separate downstream stage so restored
//    values are never re-inspected (mask-before-detokenize order).
// 5. Per-step finding counts are per scanned window: the overlap tail is
//    scanned again on the next step, so the same bytes can be counted
//    twice. Use counts as signal, not accounting; the summary's
//    countsByCategory is a signal aggregate.
//
// Zero dependencies.

import {
  detectSensitiveContent,
  detectSensitiveSpans,
  hasCriticalFinding,
} from './detect.ts';
import { detectThreats, hasCriticalThreat } from './threat.ts';

/** Bytes held back from emission so split secrets stay scannable. */
export const STREAM_OVERLAP_BYTES = 2048;
/** Inspector version, stamped in audit metadata. */
export const STREAM_INSPECTOR_VERSION = 'stream-v1';

export interface StreamChunkFinding {
  detector: string;
  category: string;
  severity: string;
  count: number;
}

export interface StreamStepResult {
  /** Sanitized text to forward downstream. '' when terminated or nothing due. */
  output: string;
  terminated: boolean;
  terminateReason: string | null;
  /** Findings from this step's scan (categories/counts only). */
  findings: StreamChunkFinding[];
}

export interface StreamSummary {
  chunks: number;
  bytes: number;
  emittedBytes: number;
  terminated: boolean;
  terminateReason: string | null;
  /** category -> total count across the stream */
  countsByCategory: Record<string, number>;
  redactions: number;
}

/**
 * Incremental streaming inspector. One instance per provider stream.
 * Not reusable after finalize().
 */
export class StreamInspector {
  private buffer = '';
  private terminated = false;
  private terminateReason: string | null = null;
  private finalized = false;
  private chunks = 0;
  private bytes = 0;
  private emittedBytes = 0;
  private redactions = 0;
  private countsByCategory: Record<string, number> = {};

  constructor(private readonly overlapBytes: number = STREAM_OVERLAP_BYTES) {}

  private recordFindings(
    contentFindings: Array<{ category: string; severity: string; count: number; detector: string }>,
    threatFindings: Array<{ category: string; severity: string; count: number; detector: string }>,
  ): StreamChunkFinding[] {
    const out: StreamChunkFinding[] = [];
    for (const f of [...contentFindings, ...threatFindings]) {
      out.push({ detector: f.detector, category: f.category, severity: f.severity, count: f.count });
      this.countsByCategory[f.category] = (this.countsByCategory[f.category] ?? 0) + f.count;
    }
    return out;
  }

  /** Scan one window; returns the verdict without mutating stream state. */
  private verdict(window: string): {
    terminate: boolean;
    reason: string | null;
    contentFindings: ReturnType<typeof detectSensitiveContent>;
    threatFindings: ReturnType<typeof detectThreats>;
  } {
    const contentFindings = detectSensitiveContent(window);
    const threatFindings = detectThreats(window);
    if (hasCriticalFinding(contentFindings)) {
      return { terminate: true, reason: 'critical secret or key detected in model output', contentFindings, threatFindings };
    }
    if (hasCriticalThreat(threatFindings)) {
      return { terminate: true, reason: 'critical threat pattern detected in model output', contentFindings, threatFindings };
    }
    if (threatFindings.some((f) => f.severity === 'high')) {
      return { terminate: true, reason: 'high-severity attack pattern detected in model output', contentFindings, threatFindings };
    }
    return { terminate: false, reason: null, contentFindings, threatFindings };
  }

  /**
   * Mask high-severity content spans in `text`. Spans are located in `text`
   * itself; a span split by the emit boundary simply won't match its regex
   * and stays in the overlap tail for a later scan.
   */
  private redactHighSpans(text: string, highCategories: Set<string>): string {
    const spans = detectSensitiveSpans(text)
      .filter((s) => highCategories.has(s.category))
      .sort((a, b) => b.start - a.start);
    if (spans.length === 0) return text;
    let out = text;
    for (const s of spans) {
      out = out.slice(0, s.start) + `[redacted:${s.category}]` + out.slice(s.end);
      this.redactions++;
    }
    return out;
  }

  inspect(chunk: string): StreamStepResult {
    if (this.terminated) {
      return { output: '', terminated: true, terminateReason: this.terminateReason, findings: [] };
    }
    if (this.finalized) {
      return { output: '', terminated: false, terminateReason: null, findings: [] };
    }
    if (typeof chunk !== 'string' || chunk.length === 0) {
      return { output: '', terminated: false, terminateReason: null, findings: [] };
    }
    this.chunks++;
    this.bytes += chunk.length;
    this.buffer += chunk;

    const v = this.verdict(this.buffer);
    const findings = this.recordFindings(v.contentFindings, v.threatFindings);
    if (v.terminate) {
      this.terminated = true;
      this.terminateReason = v.reason;
      this.buffer = '';
      return { output: '', terminated: true, terminateReason: v.reason, findings };
    }

    // Emit everything older than the overlap; the tail stays for the next scan.
    const emitUpTo = Math.max(0, this.buffer.length - this.overlapBytes);
    let emitText = this.buffer.slice(0, emitUpTo);
    const highCats = new Set(
      v.contentFindings.filter((f) => f.severity === 'high').map((f) => f.category),
    );
    if (highCats.size > 0 && emitText.length > 0) {
      emitText = this.redactHighSpans(emitText, highCats);
    }
    this.buffer = this.buffer.slice(emitUpTo);
    this.emittedBytes += emitText.length;
    return { output: emitText, terminated: false, terminateReason: null, findings };
  }

  /**
   * End of stream: scan the held-back tail once, redact high findings,
   * and emit it — unless it is critical, in which case terminate.
   */
  finalize(): StreamStepResult {
    if (this.terminated) {
      return { output: '', terminated: true, terminateReason: this.terminateReason, findings: [] };
    }
    if (this.finalized) {
      return { output: '', terminated: false, terminateReason: null, findings: [] };
    }
    this.finalized = true;
    const v = this.verdict(this.buffer);
    const findings = this.recordFindings(v.contentFindings, v.threatFindings);
    if (v.terminate) {
      this.terminated = true;
      this.terminateReason = v.reason;
      this.buffer = '';
      return { output: '', terminated: true, terminateReason: v.reason, findings };
    }
    const highCats = new Set(
      v.contentFindings.filter((f) => f.severity === 'high').map((f) => f.category),
    );
    let tail = this.buffer;
    if (highCats.size > 0 && tail.length > 0) {
      tail = this.redactHighSpans(tail, highCats);
    }
    this.buffer = '';
    this.emittedBytes += tail.length;
    return { output: tail, terminated: false, terminateReason: null, findings };
  }

  summary(): StreamSummary {
    return {
      chunks: this.chunks,
      bytes: this.bytes,
      emittedBytes: this.emittedBytes,
      terminated: this.terminated,
      terminateReason: this.terminateReason,
      countsByCategory: { ...this.countsByCategory },
      redactions: this.redactions,
    };
  }
}
