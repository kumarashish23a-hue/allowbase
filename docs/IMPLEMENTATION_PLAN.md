# Implementation Plan — security foundation

*2026-09-27. Phases follow the brief's §60 order, mapped onto what the repo
already has. Each phase ends with: typecheck, tests, build, migration check.*

## Phase 1 — Foundation: DONE (verify, don't rebuild)
`001`–`011` migrations, Supabase Auth, RLS on every table, org model,
append-only audit, request IDs, structured errors. Verification is the
existing `scripts/verify-*.mjs` suite (PGlite) — all green.

## Phase 2 — Security core: IN PROGRESS (this increment)
- [x] Request normalization — `evaluate_ai_request()` args + edge-function validation
- [x] Identity engine — JWT, API-key identity, agent attribution, role gates
- [ ] **Deterministic content detection** ← building now
  - `_shared/detect.ts` (`regex-v1`): email, phone, credit card (+Luhn),
    SSN, AWS keys, GitHub/Stripe secrets, private keys, JWTs, generic
    secret assignments. Findings carry category/severity/confidence/count —
    **never raw matched values**.
  - `012_content_detection.sql`: `ai_requests.detection_findings`,
    `content.category` policy condition (any-match semantics, like
    `data.classification`), findings threaded through both RPCs, critical
    finding ⇒ risk ≥ high.
  - Both edge functions accept optional `content` (≤100KB) and scan it.
- [x] Classification (metadata-level); content findings feed it going forward
- [x] Authorization — deny-by-default, fail-closed unknowns
- [~] Risk engine — single level today; multi-dimensional scoring is a
  later increment

## Phase 3 — Policy engine hardening: NEXT
- Policy versioning (immutable published versions, publish/rollback/disable,
  audit of who/when) — schema: `policy_versions`.
- Simulator dry-run endpoint (evaluate without enforcing or persisting).
- `MONITOR` vs `ENFORCE` organization mode.
- Explainability: per-finding reason strings in the response.

## Phase 4 — Transformation: NEXT
- `MASK`/`TOKENIZE` actions with a `privacy_tokens` table (envelope
  encryption; KMS in production, env-provided key clearly marked dev-only).
- Detokenization requires explicit authorization + audit.

## Phase 5 — AI gateway: LATER (needs a real provider key to be honest)
- Provider interface + one adapter only after it is tested against the real
  API; everything else stays `NOT_CONFIGURED`. Never mock silently.

## Phase 6 — Audit/analytics: LATER
- Risk/analytics RPCs for the dashboard (top risky users/agents/tools,
  policy block counts). Queries stay org-scoped.

## Phase 7/8/9 — RAG / MCP / agent safety: LATER
- Draw module boundaries first (tool registry, argument inspection,
  SSRF protections for outbound calls). No auto-connect to arbitrary servers.

## Phase 10 — Hardening: CONTINUOUS
- Security + tenant-isolation + failure-mode tests already exist; extend
  with rate-limit tests when rate limiting lands, SSRF tests when outbound
  calls exist.

## Non-goals for this increment
Rewriting the frontend, new backend runtime/framework, Redis/queues/KMS,
microservices, ML classifiers. The brief's own rule (§67): smallest
genuinely working security system first.
