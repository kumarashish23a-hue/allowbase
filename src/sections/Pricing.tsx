import { Check } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { pricingTiers } from '../data/mock';

interface PricingProps {
  onDemo: () => void;
}

export function Pricing({ onDemo }: PricingProps) {
  return (
    <section id="pricing" className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
      <SectionHeading
        eyebrow="Pricing"
        title="Start with the prototype. Scale with your AI footprint."
        description="Illustrative pricing for the concept. No payments are processed in this demo."
      />
      <div className="mt-12 grid gap-4 lg:grid-cols-3">
        {pricingTiers.map((tier, index) => (
          <Reveal key={tier.name} delay={index * 0.08}>
            <div
              className={`flex h-full flex-col rounded-xl border p-6 shadow-card sm:p-8 ${
                tier.featured
                  ? 'border-accent-400/50 bg-accent-500/[0.07]'
                  : 'border-line bg-ink-900/60'
              }`}
            >
              <h3 className="text-base font-semibold text-mist-100">{tier.name}</h3>
              <p className="mt-3 text-4xl font-semibold tracking-tight text-mist-100">{tier.price}</p>
              <p className="mt-2 text-sm text-mist-400">{tier.description}</p>
              <ul className="mt-6 space-y-2.5">
                {tier.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-2 text-sm text-mist-300">
                    <Check size={15} className="mt-0.5 text-mint-400" />
                    {feature}
                  </li>
                ))}
              </ul>
              <div className="mt-auto pt-8">
                {tier.name === 'Team' ? (
                  <button
                    type="button"
                    onClick={onDemo}
                    className="w-full rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-accent-ink transition hover:bg-accent-400"
                  >
                    {tier.cta}
                  </button>
                ) : (
                  <Link
                    to="/app"
                    className="block w-full rounded-xl border border-line bg-ink-950/60 px-4 py-3 text-center text-sm font-semibold text-mist-100 transition hover:border-line-strong"
                  >
                    {tier.cta}
                  </Link>
                )}
              </div>
            </div>
          </Reveal>
        ))}
      </div>
    </section>
  );
}
