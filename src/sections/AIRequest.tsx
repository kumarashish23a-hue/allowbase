import { CheckCircle2, FlaskConical, XCircle } from 'lucide-react';
import { useState } from 'react';
import { InfoModal } from '../components/PolicyModals';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { requestExamples } from '../data/mock';
import type { RequestExample } from '../types';

interface AIRequestProps {
  onSimulate: () => void;
}

export function AIRequest({ onSimulate }: AIRequestProps) {
  const [info, setInfo] = useState<{ kind: 'policy' | 'data' | 'audit'; request: RequestExample } | null>(null);

  return (
    <section className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="Request inspection"
          title="Every AI request should be understandable."
          description="See exactly what was requested, what was detected, which policy applied, and why."
        />

        <div className="mt-12 grid gap-6 lg:grid-cols-2">
          {requestExamples.map((request, index) => (
            <Reveal key={request.id} delay={index * 0.08}>
              <div className="flex h-full flex-col rounded-xl border border-line bg-ink-950/60 p-6 shadow-card sm:p-8">
                <div className="flex items-center justify-between gap-4">
                  <p className="text-xs font-semibold uppercase tracking-[0.2em] text-mist-500">
                    Simulated request
                  </p>
                  <span
                    className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-bold tracking-[0.14em] ${
                      request.decision === 'BLOCK'
                        ? 'border-rose-400/30 bg-rose-400/10 text-rose-400'
                        : 'border-mint-400/30 bg-mint-400/10 text-mint-400'
                    }`}
                  >
                    {request.decision === 'BLOCK' ? <XCircle size={14} /> : <CheckCircle2 size={14} />}
                    {request.decision === 'BLOCK' ? 'BLOCKED' : 'ALLOWED'}
                  </span>
                </div>

                <dl className="mt-6 grid grid-cols-2 gap-4 text-sm">
                  {[
                    ['User', request.user],
                    ['AI', request.ai],
                    ['Data', request.data],
                    ['Purpose', request.purpose],
                  ].map(([label, value]) => (
                    <div key={label}>
                      <dt className="text-xs uppercase tracking-[0.16em] text-mist-600">{label}</dt>
                      <dd className="mt-1 text-mist-100">{value}</dd>
                    </div>
                  ))}
                </dl>

                <div className="mt-6">
                  <p className="text-xs uppercase tracking-[0.16em] text-mist-600">Detected</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {request.detected.map((item) => (
                      <span
                        key={item}
                        className="rounded-full border border-line bg-ink-900/70 px-2.5 py-1 text-xs text-mist-300"
                      >
                        {item}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mt-6 rounded-xl border border-line bg-ink-900/70 p-4">
                  <p className="text-xs uppercase tracking-[0.16em] text-mist-600">Policy</p>
                  <p className="mt-1 text-sm text-mist-200">“{request.policy}”</p>
                  <p className="mt-2 text-sm text-mist-400">{request.reason}</p>
                </div>

                <div className="mt-6 flex flex-wrap gap-2">
                  {(
                    [
                      ['policy', 'View Policy'],
                      ['data', 'View Data'],
                      ['audit', 'View Audit Log'],
                    ] as const
                  ).map(([kind, label]) => (
                    <button
                      key={kind}
                      type="button"
                      onClick={() => setInfo({ kind, request })}
                      className="rounded-lg border border-line px-3 py-2 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100"
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal className="mt-10 text-center">
          <button
            type="button"
            onClick={onSimulate}
            className="inline-flex items-center gap-2 rounded-xl bg-accent-500 px-6 py-3.5 text-sm font-semibold text-[#06202a] shadow-card transition hover:bg-accent-400"
          >
            <FlaskConical size={16} /> Simulate AI Request
          </button>
          <p className="mt-3 text-xs text-mist-600">Interactive demo. Nothing is sent anywhere.</p>
        </Reveal>

        <InfoModal
          open={info !== null}
          kind={info?.kind ?? null}
          request={info?.request ?? null}
          onClose={() => setInfo(null)}
        />
      </div>
    </section>
  );
}
