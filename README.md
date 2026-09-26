# Data Control Plane — Prototype (Frontend + Supabase Backend)

A premium, dark-first B2B SaaS marketing site + interactive product prototype for a fictional global startup called **Data Control Plane**.

Tagline: *"Give AI access to your data — without losing control."*

> **Prototype, not production.** The UI runs standalone with realistic mock data. When pointed at a Supabase project (see Backend below), sign-in, the dashboard, policies, agents, data sources, and the request simulator switch to live data — but real external data scanning and real AI traffic interception are future phases.

## Stack

- React 19 + TypeScript + Vite
- Tailwind CSS v4
- Lucide icons
- Framer Motion (animations)
- Recharts (dashboard charts)
- Supabase (PostgreSQL, Auth, RLS, Edge Functions) — optional backend

## Run it

```bash
npm install
npm run dev
```

Build:

```bash
npm run build
```

## What's inside

- `src/sections/` — page sections: Hero, Problem, How It Works, Platform dashboard, AI request inspection, Policy Engine, AI Agents, Data Sources, Security, Developers, Use Cases, Pricing, FAQ, Final CTA, Footer
- `src/components/` — Navbar, animated architecture diagram, dashboard with Recharts, AI request simulator modal, policy/data/audit modals, policy builder, sign-in placeholder
- `src/data/mock.ts` — all mock data
- `src/utils/decision.ts` — deterministic mock policy-evaluation logic for the simulator

## Key interactions

- Animated request-inspection visualization (Company Data → Data Control Plane → AI Models)
- Interactive dashboard with time-range tabs (24h / 7d / 30d)
- "Simulate AI Request" modal with staged evaluation and ALLOW / BLOCK / REDACT outcomes
- Policy cards + demo policy builder (stored in session state only)
- Agent permission cards with pause/resume, mock data-source scan details, FAQ accordion, mobile navigation

## Backend (Supabase)

The backend lives in `supabase/` and is ready to attach to a real project:

- `supabase/migrations/` — 9 ordered migrations: core (organizations, members, profiles + auto-profile trigger), data sources/assets/findings, AI models/agents/permissions, policies, AI requests/evaluations, risk events/audit logs, RLS policies, functions (`create_organization`, `evaluate_ai_request`, dashboard RPCs), and fictional demo seed data.
- `supabase/functions/evaluate-ai-request/` — Edge Function that validates the caller's JWT, validates input, and calls the secure `evaluate_ai_request` Postgres function. The service-role key never reaches the browser.
- `src/services/` — the only place components talk to Supabase: `organizationService`, `dataSourceService`, `dataAssetService`, `aiAgentService`, `policyService`, `aiRequestService`, `riskService`, `auditService`, `dashboardService`. Every service falls back to mock data when Supabase isn't configured, so the prototype works standalone.
- `scripts/verify-sql.mjs` — applies all migrations to in-memory Postgres (PGlite) and runs end-to-end checks: schema, RLS membership gate, policy-condition matching, BLOCK/ALLOW evaluations, and dashboard RPCs. Run with `node scripts/verify-sql.mjs`.

### Connect it (Supabase project required)

```bash
# 1. Create a project at https://supabase.com, then link it:
npx supabase link --project-ref <your-project-ref>

# 2. Apply migrations (includes fictional Acme Technologies demo data):
npx supabase db push

# 3. Deploy the evaluation Edge Function:
npx supabase functions deploy evaluate-ai-request

# 4. Point the frontend at your project:
cp .env.example .env
# fill in VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY (never the service-role key)

npm run dev
```

Then: create an account via Sign in (you become organization owner), and the dashboard, policies, agents, data sources, and simulator will use live data. The simulator maps its demo selections to real models/assets and evaluates through the Edge Function.

### Security notes

- RLS is enabled on every table; users only see organizations they belong to.
- `evaluate_ai_request` re-checks organization membership server-side and never trusts `organization_id` from the client.
- Audit logs are insert-only (no UPDATE/DELETE policies).
- Never store real secrets, API keys, or customer PII in findings or request metadata.

## What's inside
