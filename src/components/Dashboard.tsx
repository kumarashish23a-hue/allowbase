import { useEffect, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { getDashboard, type DashboardData } from '../services/dashboardService';

type Range = '24h' | '7d' | '30d';

const ranges: Range[] = ['24h', '7d', '30d'];

const toneClass: Record<string, string> = {
  neutral: 'text-mist-400',
  good: 'text-mint-400',
  bad: 'text-rose-400',
  warn: 'text-amber-400',
};

const riskColors = ['#5fd0a5', '#e8b45a', '#ef7d8f'];

interface TooltipEntry {
  name?: string;
  value?: number | string;
  color?: string;
}

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: TooltipEntry[]; label?: string }) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded-xl border border-line bg-ink-950/95 px-3 py-2 text-xs shadow-panel">
      {label ? <p className="mb-1 font-semibold text-mist-200">{label}</p> : null}
      {payload.map((entry, index) => (
        <p key={`${entry.name ?? 'value'}-${index}`} className="text-mist-400">
          <span style={{ color: entry.color ?? '#8dbcff' }}>●</span> {entry.name}:{' '}
          <span className="text-mist-100">{entry.value}</span>
        </p>
      ))}
    </div>
  );
}

export function Dashboard() {
  const [range, setRange] = useState<Range>('7d');
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    getDashboard(range)
      .then((result) => {
        if (!cancelled) setData(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load the dashboard.');
      });
    return () => {
      cancelled = true;
    };
  }, [range, retryCount]);

  const metrics = data?.metrics ?? [];
  const series = data?.series ?? [];
  const riskDistribution = data?.risk ?? [];
  const modelUsage = data?.modelUsage ?? [];
  const sourceUsage = data?.sourceUsage ?? [];
  const live = data?.live ?? false;

  if (error) {
    return (
      <div className="rounded-3xl border border-rose-400/30 bg-ink-900/70 p-8 shadow-panel">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-rose-400">Dashboard unavailable</p>
        <h3 className="mt-2 text-xl font-semibold tracking-tight text-mist-100">Could not load live metrics</h3>
        <p className="mt-2 max-w-xl text-sm text-mist-400">{error}</p>
        <button
          type="button"
          onClick={() => setRetryCount((count) => count + 1)}
          className="mt-5 rounded-xl border border-line bg-ink-950/60 px-4 py-2.5 text-sm font-semibold text-mist-100 transition hover:border-line-strong"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="rounded-3xl border border-line bg-ink-900/70 p-8 shadow-panel">
        <p className="text-sm text-mist-500">Loading dashboard…</p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-3xl border border-line bg-ink-900/70 shadow-panel">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-line px-6 py-5">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-mist-500">
            Platform preview{' '}
            <span
              className={`ml-2 rounded-full border px-2 py-0.5 text-[10px] tracking-[0.14em] ${
                live ? 'border-mint-400/30 bg-mint-400/10 text-mint-400' : 'border-line text-mist-500'
              }`}
            >
              {live ? 'LIVE' : 'SIMULATED'}
            </span>
          </p>
          <h3 className="mt-1 text-xl font-semibold tracking-tight text-mist-100">One control plane for your AI data.</h3>
        </div>
        <div className="flex rounded-xl border border-line bg-ink-950/60 p-1" role="tablist" aria-label="Time range">
          {ranges.map((item) => (
            <button
              key={item}
              role="tab"
              aria-selected={range === item}
              type="button"
              onClick={() => setRange(item)}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                range === item ? 'bg-accent-500/20 text-accent-200' : 'text-mist-500 hover:text-mist-200'
              }`}
            >
              {item}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 p-6 sm:grid-cols-3 xl:grid-cols-6">
        {metrics.map((metric) => (
          <div key={metric.label} className="rounded-2xl border border-line bg-ink-950/60 p-4">
            <p className="text-xs text-mist-500">{metric.label}</p>
            <p className="mt-2 text-2xl font-semibold tracking-tight text-mist-100">{metric.value}</p>
            <p className={`mt-1 text-xs ${toneClass[metric.tone]}`}>{metric.delta}</p>
          </div>
        ))}
      </div>

      <div className="thin-scroll overflow-x-auto px-6 pb-6">
        <div className="grid min-w-[720px] gap-4 lg:grid-cols-3">
          <div className="rounded-2xl border border-line bg-ink-950/60 p-5 lg:col-span-2">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold text-mist-200">AI requests over time</h4>
              <span className="text-xs text-mist-600">{range}</span>
            </div>
            <div className="mt-4 h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={series} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
                  <defs>
                    <linearGradient id="requestsGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#5b9dff" stopOpacity={0.45} />
                      <stop offset="100%" stopColor="#5b9dff" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: '#4d5f7f', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#4d5f7f', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Area type="monotone" dataKey="requests" name="Requests" stroke="#5b9dff" strokeWidth={2} fill="url(#requestsGradient)" />
                  <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef7d8f" strokeWidth={1.5} fill="transparent" strokeDasharray="5 5" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="rounded-2xl border border-line bg-ink-950/60 p-5">
            <h4 className="text-sm font-semibold text-mist-200">Risk distribution</h4>
            <div className="mt-4 h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={riskDistribution} dataKey="value" nameKey="name" innerRadius={58} outerRadius={88} paddingAngle={4} strokeWidth={0}>
                    {riskDistribution.map((entry, index) => (
                      <Cell key={entry.name} fill={riskColors[index % riskColors.length]} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 space-y-2">
              {riskDistribution.map((entry, index) => (
                <div key={entry.name} className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-2 text-mist-400">
                    <span className="h-2 w-2 rounded-full" style={{ background: riskColors[index % riskColors.length] }} />
                    {entry.name} risk
                  </span>
                  <span className="text-mist-200">{entry.value}%</span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-line bg-ink-950/60 p-5 lg:col-span-2">
            <h4 className="text-sm font-semibold text-mist-200">AI model usage</h4>
            <div className="mt-4 h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={modelUsage} margin={{ top: 8, right: 8, bottom: 0, left: -8 }} layout="vertical">
                  <CartesianGrid stroke="rgba(148,163,184,0.12)" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#4d5f7f', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="model" width={118} tick={{ fill: '#9db0d4', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(122,162,255,0.08)' }} />
                  <Bar dataKey="requests" name="Requests" fill="#2f7de9" radius={[6, 6, 6, 6]} barSize={18} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="rounded-2xl border border-line bg-ink-950/60 p-5">
            <h4 className="text-sm font-semibold text-mist-200">Data access by source</h4>
            <div className="mt-4 h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={sourceUsage} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
                  <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
                  <XAxis dataKey="source" tick={{ fill: '#4d5f7f', fontSize: 10 }} axisLine={false} tickLine={false} interval={0} angle={-18} dy={12} height={54} />
                  <YAxis tick={{ fill: '#4d5f7f', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(122,162,255,0.08)' }} />
                  <Bar dataKey="requests" name="Requests" fill="#5fd0a5" radius={[6, 6, 0, 0]} barSize={22} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      <p className="border-t border-line px-6 py-4 text-xs text-mist-600">
        {live
          ? 'Live data from your Supabase project, aggregated by database functions.'
          : 'Simulated dashboard. All metrics and charts use mock data for this prototype.'}
      </p>
    </div>
  );
}
