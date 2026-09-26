# Data Control Plane — Working Architecture

*Based on inspection of the actual deployed implementation (frontend `2d2d498` lineage, Supabase backend migrations `001–009`, Edge Function `evaluate-ai-request`, Vercel deployment). Nothing below is assumed — every claim traces to code that was read.*

---

## 1. What the Data Control Plane is (one paragraph)

The Data Control Plane is a governance layer that sits between an organization's data and the systems that want to use it — especially AI systems. Instead of each application deciding on its own what data it may touch, every AI request passes through one central checkpoint that answers four questions: *what data is being requested, how sensitive is it, what do the organization's policies say, and should this be allowed, redacted, or blocked?* Every decision is written to an append-only audit trail. Today it is a working prototype: real multi-tenant backend (Supabase Postgres + Auth + RLS + Edge Functions) with a real deterministic policy engine, wrapped in a polished demo frontend that falls back to simulated data when no backend is configured.

---

## 2. Architecture diagram (text)

```
                         ┌─────────────────────────────────────────┐
                         │  FRONTEND (React 19 SPA, Vercel)        │
                         │  dataplane.vercel.app                   │
                         │                                         │
                         │  Landing sections + App shell           │
                         │  ┌──────────┐ ┌───────────────────┐    │
                         │  │Dashboard │ │ Request Simulator │    │
                         │  │Policies  │ │ Agents / Sources  │    │
                         │  └──────────┘ └───────────────────┘    │
                         │  services/* = single backend boundary   │
                         │  (Supabase-first, silent mock fallback) │
                         └──────────────┬──────────────────────────┘
                                        │ HTTPS, anon key only
                                        │ JWT in Authorization header
                         ┌──────────────▼──────────────────────────┐
                         │  SUPABASE (backend, no custom server)   │
                         │                                         │
                         │  ┌──────────────────────────────────┐   │
                         │  │ PostgREST (auto CRUD, RLS-gated) │   │
                         │  └───────────────┬──────────────────┘   │
                         │  ┌───────────────▼──────────────────┐   │
                         │  │ Edge Function (Deno)             │   │
                         │  │ POST /evaluate-ai-request        │   │
                         │  │ ① validate JWT ② validate input  │   │
                         │  │ ③ call RPC as the caller         │   │
                         │  └───────────────┬──────────────────┘   │
                         │  ┌───────────────▼──────────────────┐   │
                         │  │ Postgres RPCs (SECURITY DEFINER) │   │
                         │  │ • evaluate_ai_request            │   │
                         │  │ • create_organization            │   │
                         │  │ • 5 dashboard aggregates         │   │
                         │  │ • policy_condition_matches       │   │
                         │  └───────────────┬──────────────────┘   │
                         │  ┌───────────────▼──────────────────┐   │
                         │  │ RLS policies on all 15 tables    │   │
                         │  │ helpers: is_org_member,           │   │
                         │  │ has_org_role (auth.uid() based)   │   │
                         │  └───────────────┬──────────────────┘   │
                         │  ┌───────────────▼──────────────────┐   │
                         │  │ 15 tables, all tenant-scoped by   │   │
                         │  │ organization_id                  │   │
                         │  └──────────────────────────────────┘   │
                         └─────────────────────────────────────────┘

  What is NOT in the diagram (does not exist yet):
  discovery connectors, classification workers, event ingestion,
  alert delivery, lineage store, AI traffic proxy.
```

---

## 3. End-to-end request / data flow

There are two completely different flows in this system today. Confusing them is the source of most misunderstanding:

### Flow A — Governing an AI request (REAL, implemented)

This is the one real control loop. It governs *request metadata* (which model, which data asset, what purpose) — not raw data bytes.

```
User (signed in, JWT)
  → RequestSimulator form: picks AI (e.g. "Claude"), data (e.g. "Customer Database"),
    types a purpose ("generate churn report")
  → aiRequestService.evaluateRequest()
  → resolves model name → ai_models.id, data label → data_assets.id (fuzzy match, org-scoped)
  → POST Edge Function /evaluate-ai-request { organization_id, ai_model_id, purpose, data_asset_ids[] }
      → 401 if no/invalid JWT
      → 400 if UUIDs malformed, purpose > 500 chars, > 50 assets, bad request_type
      → RPC evaluate_ai_request(...) runs AS THE CALLER (anon key + user JWT)
          ① membership check: is_org_member(org_id) else raise 42501 → 403
          ② model must belong to the org, else error
          ③ sensitivity scan: any asset with sensitivity_level in
             (medium|high|critical) or classification in (confidential|restricted)?
          ④ load ACTIVE policies ordered by priority; every condition in
             policy.rule.conditions must match (AND semantics)
          ⑤ decision = most restrictive triggered action:
             block > review/redact > allow
          ⑥ risk = high | medium | low (block forces ≥ high)
          ⑦ INSERT ai_requests (+ ai_request_data links)
          ⑧ INSERT policy_evaluations (one row per triggered policy)
          ⑨ INSERT audit_logs (append-only)
         ⑩ INSERT risk_events (only on block/review/high risk)
      → returns { request_id, decision, risk, reasons, policies_triggered, checks }
  → UI shows ALLOW / REDACT / BLOCK with reason and policy name
```

Key property: **the browser never decides**. The Edge Function re-validates everything and the database function enforces membership. A tampered client can at most get a 403.

### Flow B — Everything else (dashboard, lists, CRUD)

```
Component → service (e.g. dashboardService.getDashboard())
  → getActiveOrganizationId() (cached per session; cleared on org create/sign-out)
  → PostgREST direct table reads or RPC aggregates (get_dashboard_metrics, …)
  → RLS filters every row by is_org_member(organization_id)
  → on ANY error or missing session/org: silently return MOCK data (SIMULATED badge)
```

This fallback is deliberate for the demo, and it is also the system's biggest honesty problem: a backend failure looks identical to "no data," which is why the setup checklist and LIVE/SIMULATED badge exist.

### What "data movement" means here (and doesn't)

Today the platform moves **metadata about requests**, not data itself. No customer rows, file bytes, or prompt contents ever flow through the system — by design (see `purpose max 500 chars`, no raw-data columns). Real data-plane interception (a proxy that sees actual AI traffic) does not exist yet.

---

## 4. Frontend → backend → database flow

| Frontend | Backend API | Database |
|---|---|---|
| `SignInModal` | Supabase Auth (email/password) | `auth.users` → `handle_new_user` trigger → `profiles` row |
| `ProfileModal` → create org | RPC `create_organization` | `organizations` + `organization_members` (caller → owner) |
| `SetupModal` → Load starter workspace | PostgREST inserts (normal RLS) | 2 sources, 2 assets, 2 models, 1 agent, 2 policies, 1 finding |
| `SetupModal` → Check edge function | `functions.invoke('evaluate-ai-request', {body:{}})` probe | 404 = missing; any other answer = endpoint exists |
| `RequestSimulator` → Evaluate | Edge Function → RPC `evaluate_ai_request` | `ai_requests`, `ai_request_data`, `policy_evaluations`, `audit_logs`, `risk_events` |
| `Dashboard` | RPCs `get_dashboard_metrics`, `get_requests_over_time`, `get_risk_distribution`, `get_model_usage`, `get_source_usage` | Aggregates computed in SQL; browser never fetches raw rows |
| `PolicyEngine` section | PostgREST on `policies` | rule JSONB `{conditions:[{field, operator, value}]}` |
| `Agents` section | PostgREST on `ai_agents`, `ai_agent_data_permissions` | grants exist in schema; **not consulted by the evaluator yet** |
| `DataSources` section | PostgREST on `data_sources` | labels + mock counts only — no live connectors |
| Anonymous landing | none | `src/data/mock.ts` + `src/utils/decision.ts` (keyword evaluator) |

Environment: exactly two public variables — `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`. The service-role key is never in the frontend (`.env.example` says so explicitly). Deployment: static SPA on Vercel + Supabase cloud; no custom server process exists anywhere.

---

## 5. Data discovery flow

### What discovery should be (target)

1. Organization connects a data source (OAuth / credentials via vault, **never** pasted into chat or code).
2. Platform authenticates and stores only a reference + encrypted credential handle.
3. A **discovery worker** (background job, not a UI click) enumerates databases → schemas → tables → columns (or buckets → files, APIs → endpoints, SaaS → objects).
4. Each discovered object becomes a `data_assets` row: name, location, type, owner, tags — **metadata only, never row contents**.
5. New/changed assets raise events → classification → policy review → alerts.

### What exists today (updated: Phase 2b classification, 2026-09-26)

- `data_sources` table: `{ name, type, status, metadata (jsonb), last_scan_at }`. `type = 'postgresql'` and `status = 'connected'` are real states now, not just labels.
- **Real PostgreSQL connector** — two Edge Functions, no new migrations needed:
  - `connect-postgres`: validates JWT + owner/admin/security role, tests the connection over TLS (15s timeout), saves **only** non-secret config (`host, port, database, username`) in `data_sources.metadata`. The password is used once, in memory, never stored/logged/returned.
  - `discover-postgres`: takes `{ source_id, password }`, sets the session read-only (`default_transaction_read_only = on`), reads `information_schema.tables` + `information_schema.columns` (+ best-effort `pg_stat_user_tables` row estimates), and upserts one `data_assets` row per table (`asset_type = 'table'`, columns in `metadata`, `last_scanned_at` updated). Re-discovery **preserves** manually labeled columns. No row data is ever selected or persisted.
- **Deterministic classification engine** (blueprint step 6) — `supabase/functions/_shared/classify.ts`, pure TypeScript with zero dependencies:
  - Normalizes column names (`userEmail`, `EMAIL-ADDRESS`, `"e-mail"` → one form), then applies ordered pattern/semantic rules: credentials → `restricted/critical`, card numbers/CVV/IBAN → `restricted/critical`, PII (email, phone, SSN, names, DOB, address, IP) → `confidential/high`, financial amounts → `confidential/high`, health → `restricted/high`, linkable IDs → `internal/medium`, timestamps/flags → `internal/low|none`.
  - Every verdict carries `{ classification, sensitivity, confidence, rule, category, needs_review }`. Confidence below 0.8 — or no rule match — flags the column for **human review** instead of guessing. Specific rules precede general ones (`card_token` is financial, never a credential).
  - Asset labels roll up from columns (max severity). Findings land in `sensitive_data_findings` (`finding_type` ∈ pii/financial/credential/healthcare/confidential, `severity` high/critical, `field_name` = column); only the classifier's own **open** findings are refreshed — human-resolved/ignored findings are never touched.
- **Classification entry points**: `discover-postgres` classifies on every discovery; new `classify-assets` Edge Function re-runs classification on demand (asset / source / org scope) and applies manual column overrides (`classified_by: 'manual'` — the user always wins). JWT + owner/admin/security role on both.
- The Data Sources section shows **Live** badges for connected databases, with per-source **Discover** (password per run, never stored) and **View catalog**: expandable table → column browser with per-column classification chips, confidence, review badges, a **Label…** dropdown for manual override, **Re-run classification**, and the open findings list.
- Verified with `scripts/verify-classify.mjs` (49 assertions: normalization, rule ordering, word-boundary safety, rollup, findings mapping against the DB check constraints) and `scripts/verify-discovery.mjs`.
- Still missing: OAuth connectors (Drive/GitHub/Slack/…), background/scheduled discovery workers, event ingestion pipeline, and the real enforcement point (API keys + gateway — blueprint steps 8–9).

### The metadata-vs-data rule (architectural principle)

The platform should **store metadata, never raw data**. Reasons: blast radius (a breach of the control plane must not leak customer rows), scale (you cannot copy every warehouse), and trust (customers will not grant a governor the keys to the kingdom *and* a copy of the kingdom). Today's schema obeys this: there is no column anywhere that holds customer PII, file bytes, or prompt text. Keep it that way.

---

## 6. Policy enforcement flow

Policies live in the `policies` table:

```
policies { id, organization_id, name, description, status, priority,
           action: allow|block|redact|review,
           rule: { conditions: [ { field, operator, value } ] } }
```

**Supported condition fields** (`policy_condition_matches`): `data.classification`, `data.sensitivity_level`, `ai.is_external`, `ai.is_approved`, `purpose`.
**Operators**: `equals`, `not_equals`, `in`, `not_in`. **Unknown fields fail closed** (return false so the policy author notices).

Evaluation (inside `evaluate_ai_request`, steps ④–⑤ above):

1. Active policies load in `priority ASC` order.
2. A policy triggers only if **all** its conditions match (AND). A `data.*` condition matches if **any** requested asset matches it.
3. Most restrictive triggered action wins: `block` › `review`/`redact` › `allow`.
4. Every triggered policy gets a `policy_evaluations` row with the decision, reason, and the `checks` snapshot (`identity`, `permission`, `data_classification`, `ai_destination`, `purpose`).

This maps to the requested IF/THEN shape directly:

```
IF  data.sensitivity_level in [high, critical]      -- data.*
AND ai.is_external = true                            -- ai.*
THEN block + alert (risk_events row) + log (audit_logs row)
```

**Gaps vs. the ideal**: no `quarantine` action, no time/location/device conditions, no per-user or per-group conditions. Fixed 2026-09-26 (migration 010): `require_approval` action + `approval_requests` table + `decide_approval` RPC + Approvals UI now exist; `checks.permission` is real; `ai_agent_data_permissions` grants are enforced with default deny for agents.

---

## 7. AI governance flow (the important one)

The Data Control Plane becomes "the governance layer between AI applications and organizational data" through this checkpoint model:

```
AI application (chatbot, agent, RAG pipeline)
  → wants data: "give me customers likely to churn"
  → (today: developer describes the request in the simulator)
    (target: SDK/gateway intercepts the real call)
  → CONTROL PLANE CHECKPOINT
      ① authenticate the caller (user or service identity)
      ② resolve WHICH assets the request touches (asset lookup)
      ③ classify: sensitivity from the catalog (deterministic, pre-computed)
      ④ policy check: deterministic rules → allow / redact / block
      ⑤ write audit event BEFORE/AFTER
  → ALLOW: proceed · REDACT: proceed with masked fields · BLOCK: refuse with reason
```

How each AI concern maps:

| Concern | Today | Target |
|---|---|---|
| RAG retrieval | asset-level allow/block on the *described* request | vector-DB–aware policy: filter retrieved chunks by classification before they reach the prompt |
| Vector databases | not modeled | `data_assets` rows of type `vector_index` with embedding-source lineage |
| AI agents / tool calls | `ai_agents` + `ai_agent_data_permissions` tables exist; `request_type: agent_action/tool_call` accepted by the API | evaluator enforces the grant table; tool-call arguments scanned for sensitive fields |
| Prompt data | `purpose` (≤500 chars, metadata only) | prompt *templates* registered as assets; raw prompts never stored |
| Retrieved documents | asset-level | chunk-level: each retrieval logged as `ai_request_data` with redaction flags |
| Model outputs | not inspected | output scanning worker (DWP-style) for leakage, sampled or full |
| Data leakage | prevented at request time by policy | + detective layer: output scanner + anomaly detection on access patterns |

The non-negotiable design rule: **detection (what is sensitive) should be deterministic and pre-computed** (classification labels on assets); **judgment calls** (is this purpose legitimate?) stay human in `review`. AI/ML helps in classification *suggestions* and anomaly detection — never as the sole decider on allow/block, because a probabilistic gatekeeper cannot be audited.

---

## 8. Security architecture

| Layer | Implemented | Notes / gaps |
|---|---|---|
| Authentication | Supabase Auth, email/password, JWT | No SSO/SAML, no MFA enforcement UI, no API keys for service accounts |
| Authorization | RBAC: `owner/admin/member/viewer` via `organization_members`; helpers `is_org_member`, `has_org_role`, `org_role` | No ABAC yet; `permission` check hardcoded true in evaluator |
| Tenant isolation | `organization_id` on every tenant table; RLS on all 15 tables; RPCs re-verify membership and scope queries by org | Relies on `auth.uid()` — correct; no cross-org join is possible through the API |
| Never trust client org_id | Edge Function + RPC both verify `is_org_member(p_organization_id)`; 42501 → 403 | Verified in code |
| Secrets | Anon key only in browser; service role never leaves server; Edge Function uses caller JWT | No vault integration for source credentials (none are collected yet) |
| Input validation | Edge Function: UUID regex, length caps, enum for `request_type` | Defense in depth; DB also constrains via checks |
| Audit | `audit_logs` has SELECT + INSERT policies only — **append-only from the app** | Not WORM at the storage level; a DB superuser could still alter (document, don't pretend otherwise) |
| Least privilege | `GRANT EXECUTE … TO authenticated` only; no public grants | Service-role usage: none in app paths |
| Encryption | TLS in transit; at-rest encryption is Supabase-managed | No field-level encryption; no customer-managed keys |
| Key rotation | — | Not implemented |
| Data minimization | No raw PII/prompt/secret columns exist anywhere | Enforced by schema, not just policy |
| Rate limiting / abuse | — | Not implemented (Edge Function has no throttle) |

**Cross-org leakage prevention** (the critical question): every read path is one of (a) PostgREST with RLS `is_org_member(organization_id)`, or (b) `SECURITY DEFINER` RPC that first checks `is_org_member(p_organization_id)` and then filters `WHERE organization_id = p_organization_id` with `SET search_path = public`. There is no code path that lists data without an org scope. The `full_setup.sql` seed org ("Acme") is visible only to its own members.

---

## 9. Multi-tenant architecture

```
Company A ─┐
Company B ─┼─▶ auth.users (global) ─▶ organization_members (tenant link)
Company C ─┘         │                           │
                     │                    ┌──────┴──────┐
                     │                    │  RLS: every │
                     │                    │  row check  │
                     │                    │  is_org_member│
                     │                    │  (organization_id) │
                     │                    └──────┬──────┘
                     │                           ▼
                     │              organizations, data_sources, data_assets,
                     │              ai_models, ai_agents, policies, ai_requests,
                     │              audit_logs, risk_events, … (all org-scoped)
```

Enforcement is **database-level, never frontend filtering**: RLS policies call `is_org_member(org_id)` which checks `organization_members` for `auth.uid()`. The frontend's `getActiveOrganizationId()` only chooses *which* of the user's own orgs to display. Even a fully compromised browser session can only ever see orgs the user belongs to.

---

## 10. Current implementation map

### Frontend (deployed, `dataplane.vercel.app`)

- **Landing** (anonymous): Hero, Problem, HowItWorks, animated ArchitectureDiagram, Platform preview, AIRequest hero demo, PolicyEngine, Agents, DataSources, Security, Developers (API code sample), UseCases, Pricing, FAQ, FinalCta, Footer. All **SIMULATED** by design.
- **App shell** (`App.tsx`): section navigation, auth state, `SetupModal` auto-open when setup incomplete, `Account` → profile.
- **Dashboard** (`Dashboard.tsx` + `Platform.tsx`): stat cards, Recharts bar/donut charts, time-range tabs. **LIVE** badge when RPCs succeed; **SIMULATED** otherwise.
- **RequestSimulator**: the AI-governance demo. Live path → Edge Function; fallback → keyword mock (`decision.ts`).
- **Modals**: `SignInModal` (Supabase email/password), `ProfileModal` (identity, org card, org creation for org-less users), `SetupModal` (4-step checklist: sign in → create org → load starter workspace → deploy evaluation service, with Supabase dashboard deep-links and copyable function code).
- **Performance**: route-level `lazy()` for modals + simulator; vendor code-splitting (recharts/framer-motion/supabase chunks).

### Backend (Supabase project, user-provisioned)

- **15 tables** (migrations `001–006`): orgs/members/profiles; sources/assets/findings; models/agents/agent-permissions; policies; requests/request-data/evaluations; risk events; append-only audit logs.
- **RLS** (`007`): enabled on every table; `is_org_member` / `has_org_role` / `org_role` helpers (`SECURITY DEFINER`, `auth.uid()`).
- **RPCs** (`008`): `create_organization`, `evaluate_ai_request` (the 14-step policy engine), `policy_condition_matches`, 5 dashboard aggregates — all `SECURITY DEFINER` + `SET search_path = public`, all membership-checked.
- **Edge Function** (`evaluate-ai-request`): JWT validation → input validation → RPC-as-caller. No secrets required.
- **Setup assets**: `supabase/full_setup.sql` (one-paste DB bootstrap), `supabase/starter_kit.sql` (idempotent demo workspace), `scripts/verify-sql.mjs` (PGlite-tested migrations).

### What each frontend section shows and where its data comes from

| Section | What the user sees | Data source (signed in) | Actions → backend effect |
|---|---|---|---|
| Overview/Dashboard | request counts, allow/block charts, risk donut | 5 dashboard RPCs | time-range tabs re-query |
| AI Request simulator | ALLOW/REDACT/BLOCK verdict + reasons | Edge Function → `evaluate_ai_request` | each run INSERTs request + evaluations + audit + risk rows |
| Policies | policy list, demo policy builder | `policies` table | create/pause → new/updated policy rows (evaluated on next request) |
| Agents | agent cards with risk badges | `ai_agents` | (view only today) |
| Data Sources | source list with record counts | `data_sources` | (view only; counts are manual) |
| Security | control descriptions | static | none (marketing) |
| Developers | API code sample | static | none |

---

## 11. Missing components (honest list)

1. **Discovery connectors** — PostgreSQL is real (connect + discover + classify). Still no OAuth, no credential vault, no scanner workers for MySQL/S3/SaaS/APIs.
2. **Automated classification** — deterministic rule engine is live for discovered PostgreSQL columns (pattern/semantic rules, confidence + human-review queue, manual override, findings). No ML-assisted suggestions yet, and hand-created assets still use the manual dropdown.
3. **Event ingestion** — no `access_events` table, no streaming pipeline; the only "events" are rows created by the evaluation RPC itself.
4. **Alert delivery** — `risk_events` rows exist but nothing notifies anyone (no email/webhook/Slack).
5. **Approval workflows** — `review` is a terminal label; no queue, no approver UX, no `require_approval` action.
6. **Data-access enforcement for agents** — `ai_agent_data_permissions` is schema-only; the evaluator ignores it.
7. **Lineage** — no `lineage_edges`, no source→processing→model graph.
8. **Real AI interception** — no SDK, proxy, or gateway; the simulator evaluates *descriptions* of requests.
9. **Programmatic API** — no API keys, no service accounts, no rate limits.
10. **Enterprise hardening** — no SSO/SAML, no MFA policy, no WORM audit storage, no retention automation, no key rotation, no field-level encryption.
11. **Failure honesty** — services silently fall back to mock data on error, hiding backend outages from the user.

---

## 12. Recommended next development phases

Smallest architecture that can become a real product — in order, each phase shippable alone:

- **Phase 1 — Harden the core ✅ DONE (2026-09-26).** Silent mock fallback removed: signed-in users with a workspace now get explicit errors from the dashboard and simulator (mock remains only for the signed-out landing preview). `ai_agent_data_permissions` is enforced inside `evaluate_ai_request` — agent-attributed requests without a read grant are hard-blocked (default deny), and requested asset IDs are verified to belong to the caller's organization (fail closed). New `require_approval` policy action: matching requests get status `pending_approval`, open a row in the new `approval_requests` table, and wait in the new Approvals UI section; `decide_approval` RPC (owner/admin only) moves them to allowed/blocked with an audit entry. Starter kit ships a demo `require_approval` policy plus a starter agent grant so all five simulator scenarios (block / allow / pending approval / agent denied / agent allowed) work out of the box. Migration `010_hardening.sql` (also appended to `full_setup.sql`); verified with 9 PGlite tests in `scripts/verify-sql.mjs`.
- **Phase 2 — One real connector (weeks).** Postgres/MySQL discovery worker (Supabase Edge Function on cron or small external worker): enumerate schemas/tables/columns → upsert `data_assets`, update `record_count`, write `sensitive_data_findings` from deterministic scanners (regex for emails, phones, AWS keys, etc.). *Why:* turns the catalog from typed labels into discovered truth.
- **Phase 3 — Classification assistance (weeks).** Scanner results → suggested `classification`/`sensitivity_level` with human confirm in UI. Deterministic rules first; ML suggestions later, never auto-applying to `restricted`.
- **Phase 4 — Events + alerts (weeks).** `access_events` ingestion (connector-reported + API), anomaly heuristics (new source, permission change, off-hours bulk access), and real delivery (webhook/email) for `risk_events`.
- **Phase 5 — Lineage (weeks).** `lineage_edges` populated by connectors (DBT/Airflow metadata, query logs) → source→pipeline→warehouse→AI graph in UI.
- **Phase 6 — AI interception (months).** Gateway/SDK that real AI apps call *instead of* the model API: evaluates, redacts, logs — making the simulator's flow real for production traffic.
- **Phase 7 — Enterprise (months).** SSO/SAML, API keys + service accounts, WORM audit export, retention policies, customer-managed keys. Only when a paying customer asks.

Explicitly **not** recommended: microservices, a custom Node backend (Postgres RPCs + Edge Functions cover it), blockchain audit logs, or "AI that writes your policies."

---

## 13. Complete real-world example

**Acme Corp connects its PostgreSQL production database.**

1. **Connect.** Admin opens Data Sources → Add → PostgreSQL, enters host/credentials. (Target: credentials go to a vault; the platform stores a handle. *Today: this UI doesn't exist — the source would be a typed label.*)
2. **Authenticate.** Platform connects with a read-only role, least privilege.
3. **Discover.** Worker enumerates `public.customers` → columns `email`, `phone`, `address`, `payment_information` → creates four `data_assets` rows (metadata only — no row values copied).
4. **Classify.** Deterministic scanner flags `email`/`phone` as PII, `payment_information` as financial/restricted → `sensitive_data_findings` rows → steward confirms → assets labeled `classification=restricted`, `sensitivity_level=high`.
5. **Ownership.** `data_assets.owner` set to the data-team lead; tags `pii`, `pci-adjacent`.
6. **Policy.** Admin creates policy *"Customer PII never leaves to external AI"* (priority 10, action `block`): conditions `data.classification = restricted` AND `ai.is_external = true`.
7. **AI request.** Support chatbot (model `Claude`, `is_external=true`) receives "summarize this customer's tickets" and requests the `Customer Database` asset with purpose "summarize support tickets".
8. **Checkpoint.** Edge Function → `evaluate_ai_request`: membership OK → model belongs to org → asset is `restricted`/`high` → policy conditions all match → **decision `block`**, risk `high`.
9. **Persist.** One `ai_requests` row (`blocked`), one `ai_request_data` link, one `policy_evaluations` row, one `audit_logs` row (`ai_request_block`, actor, timestamp), one `risk_events` row (`open`, severity `high`).
10. **Respond.** Chatbot gets `{ decision: "block", reasons: [...] }` and replies "I can't access customer data for this."
11. **Alert.** (Target: risk event → Slack/email to the data steward. *Today: row sits in the table.*)

**If the request had been** the internal support agent (`is_external=false`, `is_approved=true`) reading `Product Documentation` (`classification=internal`, `sensitivity=low`): no policy triggers → **decision `allow`**, risk `low`, same audit rows written. Governance is visible in both cases — that visibility *is* the product.

---

## 14. Plain-language explanation (for a non-technical founder)

Imagine your company is a bank, and your data is the money in the vault. Right now, every AI tool your teams use — chatbots, copilots, agents — walks up to the vault and takes what it wants, and nobody writes anything down. The Data Control Plane is the security desk in front of the vault. Every AI system has to check in: *who are you, what data do you want, and why?* The desk checks the rulebook your company wrote ("customer emails never go to outside AI companies"), then stamps the request **allowed**, **redacted** (you get the data with the sensitive parts blacked out), or **blocked** — and writes every decision in a permanent logbook. It never holds your actual data, only a catalog describing it, like a library index card instead of the book. Today it's a working prototype: the security desk, the rulebook, and the logbook are real and multi-tenant (each company's vault is walled off from the others at the database level), but the "cameras" that automatically discover new data and the "alarms" that notify you of violations are still on the roadmap.

---

## 15. Technical explanation (for an engineer implementing it)

**Stack.** Static React 19 SPA (Vite, Tailwind v4) on Vercel. No application server: Supabase provides Postgres 15, GoTrue Auth, PostgREST, and Deno Edge Functions. All privileged logic is in `SECURITY DEFINER` PL/pgSQL with `SET search_path = public`; the browser holds only the anon key.

**Data model (15 tables).** Tenant root: `organizations` ← `organization_members(user_id, role, status)` ← everything else carries `organization_id`. Identity: `profiles` (via `handle_new_user` trigger). Catalog: `data_sources`, `data_assets{classification, sensitivity_level}`, `sensitive_data_findings`. AI: `ai_models{is_external, is_approved}`, `ai_agents`, `ai_agent_data_permissions` (unenforced — wire it up). Governance: `policies{rule jsonb, action, priority, status}`, `policy_evaluations`, `ai_requests`, `ai_request_data`, `risk_events`, append-only `audit_logs` (SELECT+INSERT RLS only).

**Request path.** `POST /functions/v1/evaluate-ai-request` (Deno): verify JWT (`auth.getUser`), validate (UUID regexes, purpose ≤ 500 chars, ≤ 50 assets, `request_type` enum), then `rpc('evaluate_ai_request', …)` with the caller's JWT so `auth.uid()`-based RLS and `is_org_member()` hold. The RPC: membership gate (42501 → 403) → model ownership → sensitivity derived from asset labels → priority-ordered policy scan (`policy_condition_matches`: fields `data.classification|sensitivity_level`, `ai.is_external|is_approved`, `purpose`; ops `equals|not_equals|in|not_in`; AND within a policy; most-restrictive-wins across policies) → risk scoring → writes `ai_requests` + `ai_request_data` + `policy_evaluations[]` + `audit_logs` + conditional `risk_events` → returns JSON verdict. One RPC = one transaction; the verdict and its audit trail cannot diverge.

**Read path.** Dashboard aggregates run as `SECURITY DEFINER` RPCs that membership-check then aggregate in SQL — the browser never pages raw tables for metrics. Everything else is PostgREST + RLS (`is_org_member(organization_id)`).

**Multi-tenancy.** Enforced in Postgres, not the client: RLS on all tables + RPC-side `is_org_member` checks + per-query `organization_id` filters. A leaked/bypassed frontend cannot cross tenants.

**What to build next (priority).** ① Kill silent mock fallback (explicit errors; mock only for anonymous landing). ② Enforce `ai_agent_data_permissions` in the evaluator. ③ One real discovery worker (Postgres scanner → `data_assets`/`sensitive_data_findings`). ④ `access_events` ingestion + `risk_events` delivery. ⑤ Lineage edges. ⑥ AI gateway for real traffic interception. Do not add a Node backend, microservices, or LLM-driven allow/block — the deterministic engine is the correct core.

---

*End of architecture document. Last verified against code: 2026-09-26.*
