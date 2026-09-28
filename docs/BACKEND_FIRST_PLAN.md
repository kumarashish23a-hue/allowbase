# Backend-First Build Plan — AllowBase

Principle: **keep the frontend simple, make the backend the product.**
The frontend configures, observes, manages, and approves. The backend detects,
decides, transforms, enforces, and audits. All phases build inside the existing
Supabase architecture (Postgres + Edge Functions/Deno) — no rewrites, no new
backend stack (per §38 of the build brief: reuse working code).

Status key: ✅ implemented · 🟡 partial · ❌ missing
(Phase A shipped 2026-09-28: migration 025, `_shared/threat.ts`, gateway +
evaluate wiring, policy-builder keywords, `scripts/verify-threat.mjs` — 44
assertions green, tsc + build clean, no regressions.)

## Where we stand (audit 2026-09-28, main @ ac08773)

✅ Foundation (auth, orgs, roles, RLS, request IDs)
✅ Policy engine (versions, rollback, monitor/enforce, most-restrictive-wins, explainability)
✅ AI gateway (auth → rate limit → decrypt → scan → policy → mask → forward → scan response → audit)
✅ Approvals (queue, approve/reject) · ✅ Audit (append-only, no raw secrets)
✅ Rate limiting · ✅ Machine auth (023/024, gateway scope)
🟡 Detection (regex-only) · 🟡 Classification (4 levels, no highly_restricted)
🟡 Risk (single scalar) · 🟡 Transformation (mask/redact only) · 🟡 Output security (100KB cap, non-streaming)
🟡 Agent model (static permissions) · 🟡 Observability (metrics, no tracing)
❌ Threat detection · ❌ Tokenization vault · ❌ RAG security · ❌ MCP gateway

Core milestone already works: PUBLIC→ALLOW, PII→MASK, API KEY→BLOCK, all server-side.

---

## Phase A — Threat detection ✅ SHIPPED 2026-09-28

~~Entire attack class currently uncovered.~~ Now covered deterministically.

**Build:**
- `supabase/functions/_shared/threat.ts` — deterministic detector registry, `detectThreats(content)` → `{type, category, confidence, severity, detector:'threat-v1', matched_rule}`. Never stores raw secrets; stores matched rule IDs.
- Categories: `prompt_injection` ("ignore previous instructions", instruction-override), `jailbreak` (DAN-style, roleplay-escape), `system_prompt_extraction` ("reveal your instructions"), `exfiltration_attempt` (sensitive data + outbound URL/webhook co-occurrence), `malicious_instruction` (`rm -rf`, `curl|sh`, etc.), `suspicious_tool_call`.
- Wire into the evaluate pipeline (ai-gateway + evaluate-ai-request path): threat findings bump risk and feed policy.
- Migration `025_threat_detection.sql`: new policy condition `threat.category` (any-match, like `content.category`); threat findings recorded in `detection_events` with `detector='threat-v1'`.
- Policy builder: parser keywords ("prompt injection", "jailbreak", "exfiltration") → `threat.category` conditions. Frontend change is config-only.

**Tests:** `scripts/verify-threat.mjs` (~30 assertions) — true positives per category, false-positive checks, end-to-end: high-severity threat + policy → BLOCK with reasons.

**Done when:** 6 categories detected deterministically; a policy can block on `threat.category`; findings carry no raw content; tests green.

## Phase B — Quick wins ✅ SHIPPED 2026-09-28 (commit pending)

~~(one build, three holes closed)~~ All three closed.

- **B1 — Approval expiry**: `026_phase_b_quick_wins.sql` adds `approval_requests.expires_at` (default now()+24h) + `expire_stale_approvals()` (flips overdue pendings to `expired`, fails linked AI requests closed to `blocked`, writes a system audit row per expiry). Lazy expiry, no pg_cron: `decide_approval` sweeps before every decision and refuses expired approvals; ai-gateway + evaluate-ai-request sweep best-effort before each evaluation. Approvals tab shows the expiry timestamp (display only).
- **B2 — SSRF DNS pinning**: `_shared/ssrf.ts` gains `isSafeProviderUrlAsync()` — sync verdict plus resolve-then-check (every resolved A/AAAA IP must pass the blocklist), 2.5s-bounded, used by ai-gateway on every custom-provider fetch. `Deno.resolveDns` availability in the Supabase edge runtime could not be verified from here: when unavailable it falls back to the sync verdict (same protection as before, no regression). Residual honest risk: true DNS-rebinding TOCTOU between resolve and fetch (fetch has no dialer override for IP pinning with TLS SNI) — documented in the module header.
- **B3 — Duplicate model registration**: unique constraint `uq_ai_models_org_provider_name` on `(organization_id, provider, name)` after deduping (keeps earliest-created; referencing rows are `on delete set null`). Gateway's register path retries the lookup on 23505 so concurrent first-calls converge on one row.

**Tests:** `scripts/verify-phaseb.mjs` — 27 assertions green (SSRF unit incl. injected fake DNS + no-DNS fallback; PGlite: expiry sweep, decide refusal, fail-closed request, audit row, constraint + 23505).

**B1 — Approval expiry** (the `expired` status is currently dead code):
- Migration `026_approval_expiry.sql`: `approval_requests.expires_at timestamptz NOT NULL DEFAULT now() + interval '24 hours'`; SQL function `expire_stale_approvals()`; edge functions invoke it before honoring any approval (lazy expiry — no pg_cron dependency); expired approvals cannot be approved and the gateway treats them as denied.
- Frontend: Approvals tab shows expiry timestamp (display only).

**B2 — SSRF DNS pinning:**
- `_shared/ssrf.ts`: resolve hostname → pin IP for the fetch; reject private/loopback/link-local ranges. Must verify `Deno.resolveDns` availability in the Supabase edge runtime during build; if unavailable, keep the current guard and keep the residual documented (honest, not silent).

**B3 — Duplicate model registration:**
- Migration: dedupe existing rows, then unique constraint on `(organization_id, provider, model)` of `ai_models`.

**Tests:** extend existing verify scripts (expiry: approve-after-expiry fails; SSRF: private-IP hostnames rejected; models: concurrent double-register → one row).

## Phase C — Tokenization vault ✅ SHIPPED 2026-09-28 (commit pending)

Reversible PII protection for the AI gateway:

- **027**: `privacy_tokens` table (token_id `abt_tok_<22 base64url>`, AES-GCM value_encrypted + iv, purpose, created_by, 7-day default expiry, revoked_at, resolve counters) + RLS (members read metadata only; writes via service role) + `'tokenize'` added to the policy action vocabulary + `evaluate_ai_request` recreated as a 016-superset (v_tokenize/v_would_tokenize, transform priority DENY > REQUIRE_APPROVAL > REVIEW > MASK/TOKENIZE > ALLOW, tokenized/would_tokenize in metadata/audit/risk/response; diff vs 016 proves only intentional changes).
- **`_shared/tokenize.ts`** (zero-dep): `tokenize()` replaces finding-scoped spans with token ids (AES-GCM via TOKEN_ENCRYPTION_KEY, distinct token per span so frequency analysis reveals nothing); `detokenize()` restores only for the same org while unexpired/unrevoked, audits every resolve, leaves unknown tokens opaque. Findings/audits carry categories and counts — never values. New `detectSensitiveSpans()` in detect.ts (same rules/overlap as masking).
- **ai-gateway**: tokenize outbound when `evaluation.tokenized` (fails closed with 500 if TOKEN_ENCRYPTION_KEY missing — never silently downgrades); detokenize inbound AFTER masking so model-introduced secrets are still caught while token ids survive masking; token counts stamped in request metadata + response.
- Policy builder (Describe/Tap/Custom) + plain-English parser accept `tokenize`; SetupModal secret step now sets both encryption keys.
- **Tests:** `scripts/verify-tokenize.mjs` — 36 assertions green (unit: format, encrypt/decrypt round-trip, scope, expiry, revocation, cross-org isolation, wrong-key fail-closed, audit hygiene; PGlite: 001–027, allow+tokenized, mask-outranks-tokenize, monitor would_tokenize, RLS). Parser suite + all prior suites still green.

Honest limits: detokenization is per request — tokens are not shared across requests; rotating TOKEN_ENCRYPTION_KEY orphans existing tokens (they stay opaque); token ids in provider logs are unresolvable without the vault. ❌ → ✅

Mask/redact are destructive-only; real PII workflows need reversible, auditable tokenization.

**Build:**
- Migration `027_token_vault.sql`: `privacy_tokens(id, organization_id, token_id, value_encrypted, purpose, created_by, created_at, expires_at, revoked_at)`. Token format `abt_tok_<random>`; values AES-GCM encrypted; lookup by `token_id`, never by value.
- `supabase/functions/_shared/tokenize.ts`: `tokenize(text, findings, ctx)` replaces sensitive spans with token IDs; `detokenize(text, ctx)` resolves for the same org only, enforcing expiry/revocation; every resolve writes an audit row.
- New policy action `tokenize` (priority unchanged: DENY > REQUIRE_APPROVAL > TRANSFORM > ALLOW). Flow: tokenize outbound to the AI provider; detokenize inbound for the authorized org actor.
- Requires configuration: `TOKEN_ENCRYPTION_KEY` secret (documented; setup wizard probes it like `PROVIDER_ENCRYPTION_KEY`).

**Tests:** `scripts/verify-tokenize.mjs` — round-trip, expiry enforced, revocation enforced, cross-org resolve denied + audited, key rotation documented.

## Phase D — Streaming output inspection ✅ SHIPPED 2026-09-28 (commit pending)

Response-side blocking for the AI gateway's streaming path:

- **`_shared/streamInspect.ts`** (zero-dep, `stream-v1`): `StreamInspector` scans each provider chunk with a 2 KB rolling overlap buffer, so secrets split across chunk boundaries are still caught. Verdicts: critical secret/key or critical/high attack pattern → terminate (drop chunk, close provider stream, audit); high-severity secret (SSN, card, …) → redact spans in flight; medium/low → pass with counts. Findings carry categories/counts only, never values.
- **ai-gateway**: `stream: true` (OpenAI SSE / OpenAI-compatible custom providers first; 400 for others) returns `text/event-stream` (`start`/`content`/`done` events + `[DONE]`). Pipeline per chunk: SSE parse → inspector → 64-char-overlap detokenize stage (only when the request was tokenized; inspection runs BEFORE detokenization so restored values aren't re-inspected) → caller. Termination writes a `stream_terminated` audit row and stamps the request metadata with the inspector summary.
- This closes the Phase A gap for the streaming path: high/critical attack patterns in model output now terminate the stream. The non-streaming path still surfaces `threat_critical` in metadata only (documented in-code).
- **Tests:** `scripts/verify-streaming.mjs` — 29 assertions green (clean passthrough, boundary-split secrets, terminate + audit hygiene, in-flight redaction, jailbreak termination, token-id passthrough, tiny-overlap boundary, finalize flush, empty chunks).
- **Honest residuals** (in module header + docs): termination isn't retroactive; padding > 2 KB between secret halves defeats reassembly (locked in by test 9); encoded exfiltration defeats regex; per-step counts can double-count the overlap tail (signal, not accounting). 🟡 → ✅ (hardest phase)

Current output scan caps at 100KB, non-streaming — an exfiltration window on long responses.

**Build:**
- Gateway streaming path: for SSE/chunked provider responses, scan incrementally with an overlap buffer (~2KB) to catch patterns split across chunk boundaries; on critical finding → terminate stream + security event + audit; on high → redact the chunk.
- Start with OpenAI SSE behind the existing provider abstraction; other providers follow the same interface.
- Honest limit: chunked scanning is not perfect against adversarial chunk splits; the overlap buffer mitigates, documented as residual.

**Tests:** simulated chunked stream with secrets split mid-token across chunks; termination + audit verified.

## Phase E — RAG security ❌ → ✅

**Build:**
- Migration `028_rag_security.sql`: `documents`, `document_chunks` (pgvector embedding + `classification`, `owner_acl`, `organization_id`), `retrieval_policies`.
- Ingest API: document → detect → classify → chunk → embed → store with classification + ACL. Never retrieve on semantic similarity alone.
- Retrieval API: query → embed → similarity search **filtered by** `(org_id, requester clearance ≥ chunk classification, explicit grants)` → policy check → context to LLM.
- Requires configuration: embedding provider/model (documented; pgvector extension on Supabase).

## Phase F — MCP gateway ❌ → ✅

**Build:**
- Migration `029_mcp_security.sql`: `mcp_servers`, `mcp_tools`, `mcp_tool_calls`.
- New edge function `mcp-gateway`: auth → tool identification → argument inspection (`detect.ts`) → threat check → policy → ALLOW / TRANSFORM / APPROVAL / BLOCK → execute → output inspection.
- Dangerous operations (`delete`, `drop`, `export`, `transfer`, `execute`) default to `require_approval`.

## Phase G — Agent guardrails 🟡 → ✅

**Build:**
- Migration `030_agent_guardrails.sql`: extend `ai_agents` (`max_tool_calls_per_window`, `max_data_volume_bytes`, `allowed_tools`, `blocked_tools`, `approval_required_for`); new `agent_tool_calls` log.
- `supabase/functions/_shared/agentGuard.ts`: loop detection (N identical calls), call/volume caps, privilege-escalation signals; enforced in gateway paths; violations → BLOCK + security event.

---

## Cross-cutting rules (every phase)

- Each phase: migration + code + verify script + docs update + commit + push. Frontend changes are observe/configure-only (new event types render, new policy keywords); **no security logic in the frontend, ever.**
- Performance: deterministic → local rules → ML/embeddings → external LLM last. No external LLM per security decision.
- Fail-safe: restricted data + engine failure = BLOCK, never silent allow.
- Per-phase report in the §41 format: IMPLEMENTED / PRESERVED / PARTIAL / MOCKED / NOT IMPLEMENTED / REQUIRES CONFIGURATION / SECURITY RISKS / TEST RESULTS. Never claim production-ready without verification.
- Explicitly out of scope: standalone Node backend (Supabase stays), ML-based detection (deterministic first), microservice split (modular monolith holds).

## Order and rationale

A → B → C → D → E → F → G.
Threat detection first (uncovered attack class), then cheap hole-closes, then the vault (real PII workflows need it), then streaming (hard), then new surfaces in dependency order (RAG feeds agents; agents use MCP).
