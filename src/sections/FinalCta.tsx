import { ArrowRight, Check, FlaskConical } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Reveal } from '../components/Reveal';

interface FinalCtaProps {
  onDemo: () => void;
}

const ctaAssurances = ['Metadata-only discovery', 'Deterministic enforcement', 'Deny by default'];

export function FinalCta({ onDemo }: FinalCtaProps) {
  return (
    <section id="get-started" className="border-t border-line">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <Reveal>
          <div className="relative overflow-hidden rounded-xl border border-line bg-ink-900/70 px-6 py-14 text-center shadow-panel sm:px-12 lg:py-20">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(640px_320px_at_50%_0%,rgba(34,211,238,0.22),transparent_70%)]" />
            <div className="relative mx-auto max-w-3xl">
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-accent-600">Get started</p>
              <h2 className="mt-4 text-balance text-3xl font-semibold tracking-tight text-mist-100 sm:text-4xl lg:text-5xl">
                AI shouldn't mean giving up control of your data.
              </h2>
              <p className="mx-auto mt-5 max-w-xl text-base leading-relaxed text-mist-400 sm:text-lg">
                Build with AI. Move faster. Keep your data under control.
              </p>
              <ul className="mt-6 flex flex-wrap items-center justify-center gap-x-6 gap-y-2">
                {ctaAssurances.map((assurance) => (
                  <li key={assurance} className="inline-flex items-center gap-1.5 text-xs font-medium text-mist-500">
                    <Check size={14} className="text-accent-600" strokeWidth={2.5} />
                    {assurance}
                  </li>
                ))}
              </ul>
              <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
                <Link
                  to="/app"
                  className="btn-primary inline-flex w-full items-center justify-center gap-2 rounded-xl bg-accent-500 px-6 py-3.5 text-sm font-semibold text-accent-ink transition hover:bg-accent-400 sm:w-auto"
                >
                  Get Started <ArrowRight size={16} />
                </Link>
                <button
                  type="button"
                  onClick={onDemo}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-xl border border-line bg-ink-950/60 px-6 py-3.5 text-sm font-semibold text-mist-100 transition hover:border-line-strong sm:w-auto"
                >
                  <FlaskConical size={16} /> Request Demo
                </button>
              </div>
              <p className="mt-4 text-xs text-mist-600">Demo opens the interactive AI request simulator.</p>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
