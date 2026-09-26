import { useState } from 'react';
import { Modal } from '../components/Modal';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { connectedSources } from '../data/mock';
import type { DataSource } from '../types';

const riskTone: Record<DataSource['risk'], string> = {
  Low: 'text-mint-400 border-mint-400/30 bg-mint-400/10',
  Medium: 'text-amber-400 border-amber-400/30 bg-amber-400/10',
  High: 'text-rose-400 border-rose-400/30 bg-rose-400/10',
};

export function DataSources() {
  const [selected, setSelected] = useState<DataSource | null>(null);

  return (
    <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
      <SectionHeading
        eyebrow="Data sources"
        title="Know where your data lives."
        description="Every connection below is a mock integration for this prototype — no real OAuth or credentials."
      />

      <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {connectedSources.map((source, index) => (
          <Reveal key={source.id} delay={index * 0.05}>
            <div className="flex h-full flex-col rounded-2xl border border-line bg-ink-900/60 p-6 shadow-card transition hover:border-line-strong">
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-base font-semibold text-mist-100">{source.name}</h3>
                <span className="rounded-full border border-line bg-ink-950/70 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-mist-500">
                  Mock
                </span>
              </div>
              <p className="mt-1 text-xs text-mist-500">{source.category}</p>
              <dl className="mt-5 space-y-2.5 text-sm">
                {[
                  ['Records', source.records],
                  ['Sensitive assets', source.sensitiveAssets],
                  ['Last scan', source.lastScan],
                ].map(([label, value]) => (
                  <div key={label} className="flex items-center justify-between gap-3">
                    <dt className="text-mist-500">{label}</dt>
                    <dd className="text-right text-mist-200">{value}</dd>
                  </div>
                ))}
              </dl>
              <div className="mt-5 flex items-center justify-between">
                <span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${riskTone[source.risk]}`}>
                  {source.risk.toUpperCase()}
                </span>
                <button
                  type="button"
                  onClick={() => setSelected(source)}
                  className="rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100"
                >
                  View scan
                </button>
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      <Modal
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected ? `${selected.name} — mock scan` : 'Mock scan'}
        subtitle="Simulated discovery results. No real system was scanned."
      >
        {selected ? (
          <div className="space-y-3 text-sm">
            {[
              ['Category', selected.category],
              ['Records', selected.records],
              ['Sensitive assets', selected.sensitiveAssets],
              ['Last scan', selected.lastScan],
              ['Risk', selected.risk],
            ].map(([label, value]) => (
              <div key={label} className="flex items-center justify-between gap-4 rounded-xl border border-line bg-ink-950/60 px-4 py-3">
                <span className="text-mist-500">{label}</span>
                <span className="text-right text-mist-100">{value}</span>
              </div>
            ))}
          </div>
        ) : null}
      </Modal>
    </section>
  );
}
