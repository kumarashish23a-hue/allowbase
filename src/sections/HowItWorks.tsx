import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { howSteps } from '../data/mock';

export function HowItWorks() {
  return (
    <section id="how" className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="How it works"
          title="Control what AI can see. Control what AI can do."
          description="Discover, govern, and secure how AI systems access your organization's data."
        />
        <div className="relative mt-14">
          <div className="absolute bottom-8 left-[27px] top-8 hidden w-px bg-line lg:block" aria-hidden="true" />
          <div className="space-y-6">
            {howSteps.map((step, index) => (
              <Reveal key={step.index} delay={index * 0.06}>
                <div className="relative grid gap-6 rounded-xl border border-line bg-ink-950/60 p-6 sm:p-8 lg:grid-cols-[80px_1fr_1fr] lg:items-start">
                  <div className="flex lg:justify-center">
                    <span className="flex h-14 w-14 items-center justify-center rounded-xl border border-accent-400/40 bg-accent-500/10 text-sm font-bold text-accent-600">
                      {step.index}
                    </span>
                  </div>
                  <div>
                    <h3 className="text-xl font-semibold tracking-tight text-mist-100">{step.title}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-mist-400">{step.description}</p>
                    {step.example ? (
                      <p className="mt-4 rounded-xl border border-line bg-ink-900/70 px-4 py-3 text-sm text-accent-600">
                        {step.example}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex flex-wrap gap-2 lg:justify-end">
                    {step.items.map((item) => (
                      <span
                        key={item}
                        className="rounded-full border border-line bg-ink-900/70 px-3 py-1.5 text-xs text-mist-300"
                      >
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
