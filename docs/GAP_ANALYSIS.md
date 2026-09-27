# Gap Analysis — brief requirements vs. actual repository

*2026-09-27. "Have" = implemented, live, and tested. "Partial" = real but
incomplete. "Missing" = not present (and not faked — nothing in the repo
pretends otherwise).*

## Security core (brief §§3–7, 16–23, 30–39, 44–50)

| Requirement | Status | Notes |
|---|---|---|
| `POST /security/evaluate` central path | **Have** | `evaluate-ai-request` (JWT) + `ingest-event` (API key) → one `evaluate_ai_request()` engine |
| Canonical request model + requestId | **Have** | `ai_requests` row per evaluation; `request_id` in every response/audit |
| Multi-tenancy + RLS | **Have** | Tested cross-tenant denial in `verify-sql.mjs` |
| Identity (org/user/role/service/API key/agent) | **Have** | Auth JWT, API-key identity, agent attribution, role gates |
| Deterministic PII/secret **content** detection | **Missing** | ← the gap this increment closes |
| Classification | **Have** | Metadata/column-level (`rules-v1`); content-level arrives with detection |
| Security context | **Partial** | identity+asset+model+purpose captured; no device/network/time context |
| Policy engine (precedence, conflicts) | **Have** | Priority order, most-restrictive-wins; DENY > REVIEW > ALLOW |
| Policy versioning | **Missing** | Policies mutate in place |
| Policy simulator / dry-run | **Missing** | Simulator UI exists but runs live evaluations |
| Risk engine | **Partial** | Single level; not multi-dimensional |
| ALLOW/BLOCK/REDACT | **Have** | `redact` maps to review workflow |
| MASK / TOKENIZE / vault | **Missing** | No transformation of content, no vault |
| REQUIRE_APPROVAL | **Have** | Full workflow: request → approve/reject → audit |
| Audit logging (append-only) | **Have** | `audit_logs`, insert-only RLS |
| Rate limiting | **Missing** |  |
| Idempotency | **Have** | `event_id` + advisory lock |
| Structured errors, no leaks | **Have** | Vague 401s, mapped error codes |
| Explainability | **Partial** | Reasons + triggered policies returned; no per-finding explanation yet |
| Tenant-isolation tests | **Have** | In `verify-sql.mjs` |
| Fail-safe semantics | **Partial** | Fail-closed on unknown agent/asset/org; no explicit engine-down policy |

## Integration modes (brief §5)

| Mode | Status |
|---|---|
| A — Evaluation API | **Have** (live, dogfooded) |
| B — AI Gateway | **Missing** (no provider calls are proxied) |
| C — SDK / middleware | **Missing** |
| D — Provider adapters | **Missing** (correctly absent — nothing mocked) |
| E — MCP gateway | **Missing** |
| F — RAG gateway | **Missing** |

The product honestly presents itself as **Mode A** (the frontend calls it an
evaluation API, not an inline proxy). Modes B–F are not claimed anywhere.

## Extended engines (brief §§10–15, 24–29)

| Engine | Status |
|---|---|
| Detector interface + deterministic detectors | **Missing** → added this increment (`_shared/detect.ts`, `regex-v1`) |
| ML/embedding/LLM detectors | **Missing** — deliberately deferred; deterministic first per brief §11 |
| Threat engine (prompt injection…) | **Missing** |
| Transformation engine | **Missing** (beyond `redact` decision) |
| Privacy token vault | **Missing** |
| AI provider abstraction | **Missing** |
| Output security | **Missing** (evaluation is input-side) |
| MCP / RAG security | **Missing** |

## What changes in this increment
1. `supabase/functions/_shared/detect.ts` — deterministic content detectors.
2. `supabase/migrations/012_content_detection.sql` — `detection_findings` on
   `ai_requests`, new `content.category` policy condition field, findings
   threaded through `evaluate_ai_request` and `ingest_api_event`, risk bump
   on critical findings.
3. Both edge functions accept optional bounded `content` and scan it.
4. Starter-kit policy: block secrets in content bound for external models
   (new setups only — existing orgs unchanged).
5. `scripts/verify-detect.mjs` — detector unit tests + PGlite policy test.

## Deliberately not built (no demonstrated need yet)
MCP/RAG gateways, provider adapters, streaming, KMS vault, ML classifiers,
rate limiting, policy versioning, dry-run mode. Each is a follow-up increment
that plugs into the interfaces stabilized here — not a rewrite.
