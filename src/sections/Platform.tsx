import { lazy, Suspense } from 'react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';

// Below the fold: keep recharts out of the landing page's critical path.
const Dashboard = lazy(() => import('../components/Dashboard').then((m) => ({ default: m.Dashboard })));

export function Platform() {
  return (
    <section id="platform" className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
      <SectionHeading
        eyebrow="Platform"
        title="One home base for your AI data."
        description="A realistic operations view of AI requests, policy decisions, risk, and data access — simulated with mock data."
      />
      <Reveal delay={0.1} className="mt-12">
        <Suspense fallback={<div className="h-[32rem] rounded-2xl border border-line bg-ink-900/40" aria-hidden="true" />}>
          <Dashboard />
        </Suspense>
      </Reveal>
    </section>
  );
}
