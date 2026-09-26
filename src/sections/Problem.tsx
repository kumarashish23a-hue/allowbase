import { Bot, DatabaseZap, ScanSearch, ShieldAlert } from 'lucide-react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { problems } from '../data/mock';

const icons = [DatabaseZap, Bot, ShieldAlert, ScanSearch];

export function Problem() {
  return (
    <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
      <SectionHeading
        eyebrow="The problem"
        title="AI made data more powerful. It also made data harder to control."
        description="Your data is everywhere. AI is accessing more of it every day. You need a control layer."
      />
      <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {problems.map((problem, index) => {
          const Icon = icons[index % icons.length];
          return (
            <Reveal key={problem.title} delay={index * 0.08}>
              <div className="h-full rounded-xl border border-line bg-ink-900/60 p-6 shadow-card transition hover:border-line-strong">
                <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-line bg-ink-800 text-accent-600">
                  <Icon size={18} />
                </span>
                <h3 className="mt-5 text-base font-semibold text-mist-100">{problem.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-mist-400">{problem.description}</p>
              </div>
            </Reveal>
          );
        })}
      </div>
    </section>
  );
}
