# Data Control Plane — Frontend Prototype

A premium, dark-first B2B SaaS marketing site + interactive product prototype for a fictional global startup called **Data Control Plane**.

Tagline: *"Give AI access to your data — without losing control."*

> **This is a frontend-only prototype.** There are no real integrations, authentication, databases, payments, or AI interception. Everything runs locally in the browser with realistic mock data, and simulated functionality is labeled as such in the UI.

## Stack

- React 19 + TypeScript + Vite
- Tailwind CSS v4
- Lucide icons
- Framer Motion (animations)
- Recharts (dashboard charts)

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
