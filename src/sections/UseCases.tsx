import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { useCases } from '../data/mock';

export function UseCases() {
  return (
    <section id="solutions" className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="Solutions"
          title="Built for every team adopting AI."
          description="The same control plane, applied to the risks each team cares about most."
        />
        <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {useCases.map((useCase, index) => (
            <Reveal key={useCase.title} delay={index * 0.06}>
              <div className="h-full rounded-xl border border-line bg-ink-950/60 p-6 shadow-card transition hover:border-line-strong sm:p-8">
                <h3 className="text-lg font-semibold tracking-tight text-mist-100">{useCase.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-mist-400">{useCase.description}</p>
                <ul className="mt-5 space-y-2">
                  {useCase.points.map((point) => (
                    <li key={point} className="flex items-center gap-2 text-sm text-mist-300">
                      <span className="h-1.5 w-1.5 rounded-full bg-accent-400" />
                      {point}
                    </li>
                  ))}
                </ul>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
