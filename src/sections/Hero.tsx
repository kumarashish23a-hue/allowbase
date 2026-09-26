import { ArrowRight, Play } from 'lucide-react';
import { aiStack } from '../data/mock';
import { ArchitectureDiagram } from '../components/ArchitectureDiagram';
import { Reveal } from '../components/Reveal';

export function Hero() {
  return (
    <section id="top" className="relative overflow-hidden pt-16">
      <div className="mx-auto max-w-7xl px-4 pb-16 pt-16 sm:px-6 sm:pt-20 lg:px-8 lg:pb-24 lg:pt-24">
        <Reveal className="mx-auto max-w-4xl text-center">
          <span className="inline-flex items-center gap-2 rounded-full border border-line bg-ink-900/70 px-4 py-1.5 text-[11px] font-semibold uppercase tracking-[0.22em] text-accent-300">
            AI Data Infrastructure
          </span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight text-mist-100 sm:text-5xl lg:text-6xl lg:leading-[1.05]">
            Give AI access to your data — without losing control.
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-base leading-relaxed text-mist-400 sm:text-lg">
            One control layer for discovering, governing, monitoring, and securing how AI systems access your
            organization's data.
          </p>
          <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <a
              href="#get-started"
              className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-accent-500 px-6 py-3.5 text-sm font-semibold text-white shadow-card transition hover:bg-accent-400 sm:w-auto"
            >
              Get Started <ArrowRight size={16} />
            </a>
            <a
              href="#platform"
              className="inline-flex w-full items-center justify-center gap-2 rounded-xl border border-line bg-ink-900/60 px-6 py-3.5 text-sm font-semibold text-mist-100 transition hover:border-line-strong hover:bg-ink-800 sm:w-auto"
            >
              <Play size={16} /> Explore Platform
            </a>
          </div>
        </Reveal>

        <Reveal delay={0.15} className="mx-auto mt-14 max-w-4xl text-center">
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-mist-600">
            Works with your existing AI stack
          </p>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-x-8 gap-y-3">
            {aiStack.map((name) => (
              <span key={name} className="text-sm font-semibold tracking-wide text-mist-500">
                {name}
              </span>
            ))}
          </div>
          <p className="mt-3 text-[11px] text-mist-600">Illustrative names only. No partnerships implied.</p>
        </Reveal>

        <Reveal delay={0.2} className="mt-12">
          <ArchitectureDiagram />
        </Reveal>
      </div>
    </section>
  );
}
