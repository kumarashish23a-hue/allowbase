# Architecture Assessment — Data Control Plane

*Written 2026-09-27 from direct inspection of `~/workspace/dataplane`
(branch `main`, commit `60b769e`). Every claim traces to code that was read.
Companion to `docs/architecture.md` (the working architecture) — this file is
the security-foundation assessment requested by the backend build brief.*

## 1. What actually exists

### Frontend
React 19 + TypeScript + Vite + Tailwind v4 SPA on Vercel (`dataplane.vercel.app`),
two pages (`/` marketing, `/app` console). Supabase-first service layer
(`src/services/*`) with mock fallback only for signed-out visitors. No backend
framework of its own — all server logic lives in Supabase.

### Backend (all real, all live on Supabase project `xusjrmruvzfwyaxtxylw`)
- **Postgres + Auth + RLS.** 11 migrations (`001`–`011`):
  `organizations`, `organization_members`, `profiles`, `data_sources`,
  `data_assets`, `sensitive_data_findings`, `ai_models`, `ai_agents`,
  `ai_agent_data_permissions`, `policies`, `ai_requests`, `ai_request_data`,
  `policy_evaluations`, `approval_requests`, `risk_events`, `audit_logs`
  (append-only), `api_keys`.
- **Policy engine (SQL, deterministic):** `evaluate_ai_request()` —
  membership check, cross-org asset rejection (fail closed), agent data-permission
  enforcement (default deny), JSONB policy rules with priority ordering,
  most-restrictive-wins (`block` > `review`/`redact` > `allow`), risk scoring,
  per-policy evaluation rows, audit row, risk-event row. Patched in `010`/`011`
  without changing the deterministic core.
- **API keys:** `api_keys` table stores SHA-256 hash only; `create_api_key`
  (owner/admin, `dcp_live_` + 32 random bytes, plaintext returned once),
  `revoke_api_key`; keys are revoked, never deleted; expiry, scopes,
  `last_used_at` supported.
- **Ingestion (front door):** `ingest-event` Edge Function (`x-api-key` auth,
  strict validation, `verify_jwt=false`) → `ingest_api_event()` RPC
  (service_role only): key-hash auth, org resolved from the key, advisory-lock
  idempotency on `event_id`, model find-or-provision, unknown agents fail
  closed, per-call audit row with `actor_type='system'`.
- **Evaluation (JWT path):** `evaluate-ai-request` Edge Function validates the
  caller's JWT and delegates to the same `evaluate_ai_request()` RPC.
- **Deterministic classification:** `supabase/functions/_shared/classify.ts`
  (zero-dependency, `rules-v1`) classifies discovered DB columns; confidence
  < 0.8 is flagged for human review, never guessed. Applied during
  `discover-postgres` and on demand via `classify-assets`.
- **Approvals:** `require_approval` policy action → `approval_requests` row →
  `decide_approval` RPC (owner/admin, audited, expiring).
- **Tests:** `scripts/verify-{sql,discovery,classify,api-keys,remove-demo}.mjs`
  run against PGlite (in-memory Postgres) — RLS gates, policy decisions,
  idempotency, key lifecycle all asserted. `npm run build` + `oxlint` clean.

### Reusable as-is
Everything above. The brief's rule is `reuse > refactor > extend > replace`,
and the existing core already satisfies large parts of its Phase 1–3.

## 2. Assessment per brief category

| Area | Verdict |
|---|---|
| Multi-tenancy, RLS, tenant isolation | **Existing** — `organization_id` on every table, RLS everywhere, tests assert cross-tenant denial |
| Authentication (JWT + API keys) | **Existing** — Supabase Auth + hash-only API keys with scopes/expiry/revocation |
| Server-side authorization | **Existing** — RPCs check `is_org_member` / `has_org_role`; client claims never trusted |
| Deterministic detection | **Missing** — classification covers *column names*; nothing scans *content* (prompts, payloads) for PII/secrets |
| Classification | **Existing** (metadata-level) |
| Policy engine | **Existing**, needs extension — no versioning, no simulator dry-run endpoint, no transformation beyond `redact`/`review` |
| Risk engine | **Partial** — single low/medium/high/critical level, not multi-dimensional |
| Transformations (mask/tokenize) | **Missing** — `redact` exists as a decision; no mask/tokenize/vault |
| Audit | **Existing** — append-only `audit_logs`, per-decision rows |
| Approvals | **Existing** — expiring, audited, no self-approval bypass noted |
| Idempotency | **Existing** — `event_id` advisory-lock replay |
| Rate limiting | **Missing** |
| Request IDs / correlation | **Existing** — `request_id` returned and stored everywhere |
| AI provider adapters | **Missing** — correctly absent; nothing fake exists |
| MCP / RAG gateways | **Missing** — correctly absent; module boundaries not yet drawn |
| Streaming | **Missing** |
| Threat engine (prompt injection etc.) | **Missing** |
| KMS / token vault | **Missing** — no encryption infra beyond pgcrypto hashing |

## 3. Unsafe / needs work
- **Content is never inspected.** A request carrying `sk_live_...` in its
  payload is evaluated on metadata only. This is the single biggest gap
  between the current system and a "data firewall".
- **No rate limiting** on `ingest-event` (abuse / cost-explosion vector).
- **Policies are mutable in place** — no versioning, so historical decisions
  can't be reproduced against the exact policy text that made them.
- **No dry-run/monitor mode** — every evaluation enforces.
- Frontend copy in a few places still describes mock behavior (non-security,
  noted for cleanup, not in scope here).

## 4. What this assessment authorizes
Extend — do not replace — the existing engine:
1. Add deterministic **content detection** (this is the missing Phase-2 piece).
2. Wire findings into policy matching as a new condition field.
3. Keep every existing guarantee: RLS, deny-by-default, append-only audit,
   idempotency, hash-only keys.

Explicitly **out of scope** for this increment (enterprise surface, no
demonstrated need yet): MCP gateway, RAG gateway, provider adapters,
streaming, KMS-backed token vault, ML/LLM classifiers. Interfaces for these
can be drawn later without rewriting the core.
