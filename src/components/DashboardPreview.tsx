import { Activity } from 'lucide-react';

const stats = [
  { label: 'Data Assets', value: '248' },
  { label: 'AI Access', value: '37' },
  { label: 'Policies', value: '142' },
  { label: 'Alerts', value: '3' },
];

const activity = [
  { actor: 'GPT-5', asset: 'customer_db', decision: 'ALLOWED' as const },
  { actor: 'Agent-04', asset: 'financial_data', decision: 'BLOCKED' as const },
  { actor: 'Claude', asset: 'analytics', decision: 'ALLOWED' as const },
];

export function DashboardPreview() {
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-ink-900/80 shadow-card">
      <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <Activity size={15} className="text-accent-300" />
          <p className="text-xs font-bold uppercase tracking-[0.18em] text-mist-200">Data Control Plane</p>
        </div>
        <span className="rounded-md border border-line bg-ink-800 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-mist-500">
          Illustrative preview
        </span>
      </div>

      <dl className="grid grid-cols-2 border-b border-line lg:grid-cols-4">
        {stats.map((stat, index) => (
          <div
            key={stat.label}
            className={`px-5 py-4 ${index > 0 ? 'border-l border-line' : ''} ${index === 2 ? 'max-lg:border-l-0 max-lg:border-t max-lg:border-line' : ''} ${index === 3 ? 'max-lg:border-t max-lg:border-line' : ''}`}
          >
            <dt className="text-[11px] font-semibold uppercase tracking-[0.14em] text-mist-500">{stat.label}</dt>
            <dd className="mt-1 font-mono text-2xl font-semibold text-mist-100">{stat.value}</dd>
          </div>
        ))}
      </dl>

      <div className="px-5 py-4">
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-mist-500">AI access activity</p>
        <div className="thin-scroll -mx-5 mt-3 overflow-x-auto px-5">
          <table className="w-full min-w-[420px] border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-line text-[11px] uppercase tracking-[0.12em] text-mist-600">
                <th scope="col" className="py-2 pr-4 font-semibold">Actor</th>
                <th scope="col" className="py-2 pr-4 font-semibold">Data asset</th>
                <th scope="col" className="py-2 font-semibold">Decision</th>
              </tr>
            </thead>
            <tbody>
              {activity.map((row) => (
                <tr key={`${row.actor}-${row.asset}`} className="border-b border-line/60 last:border-0">
                  <td className="py-2.5 pr-4 font-mono text-[13px] text-mist-200">{row.actor}</td>
                  <td className="py-2.5 pr-4 font-mono text-[13px] text-mist-400">{row.asset}</td>
                  <td className="py-2.5">
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold tracking-wide ${
                        row.decision === 'ALLOWED'
                          ? 'border-mint-400/30 bg-mint-400/10 text-mint-400'
                          : 'border-rose-400/30 bg-rose-400/10 text-rose-400'
                      }`}
                    >
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${row.decision === 'ALLOWED' ? 'bg-mint-400' : 'bg-rose-400'}`}
                        aria-hidden="true"
                      />
                      {row.decision}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[11px] text-mist-600">Demo data for illustration only — not real metrics.</p>
      </div>
    </div>
  );
}
