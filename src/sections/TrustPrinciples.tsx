import { EyeOff, Scale, ShieldX } from 'lucide-react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';

const guarantees = [
  {
    icon: EyeOff,
    title: 'We never see your data',
    description:
      'Discovery reads metadata only — table names, column names, types. Your row data is never read, copied, or stored. There is nothing to leak.',
  },
  {
    icon: Scale,
    title: 'Deterministic enforcement',
    description:
      'Access decisions come from explicit, versioned policies you write — not from a model guessing. The same request gets the same decision, every time.',
  },
  {
    icon: ShieldX,
    title: 'Deny by default',
    description:
      'No grant means no access. Every unpermitted request is blocked and written to an append-only audit log that only you control.',
  },
];

/**
 * The trust centerpiece: structural guarantees drawn from the actual
 * architecture, placed early in the page before the product tour.
 */
export function TrustPrinciples() {
  return (
    <section aria-labelledby="trust-heading" className="border-b border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="Why teams trust us"
          title={<span id="trust-heading">Guarantees, not promises.</span>}
          description="Trust shouldn't be a claim. These properties are structural — built into the architecture itself."
        />
        <Reveal delay={0.1} className="mt-12">
          <div className="grid overflow-hidden rounded-xl border border-line bg-ink-950/70 shadow-card lg:grid-cols-3 lg:divide-x lg:divide-line">
            {guarantees.map((guarantee) => {
              const Icon = guarantee.icon;
              return (
                <div key={guarantee.title} className="border-t border-line p-8 first:border-t-0 sm:p-10 lg:border-t-0">
                  <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-line bg-ink-800 text-accent-600">
                    <Icon size={20} strokeWidth={1.75} />
                  </span>
                  <h3 className="mt-5 text-lg font-semibold tracking-tight text-mist-100">{guarantee.title}</h3>
                  <p className="mt-3 text-[15px] leading-relaxed text-mist-400">{guarantee.description}</p>
                </div>
              );
            })}
          </div>
        </Reveal>
      </div>
    </section>
  );
}
