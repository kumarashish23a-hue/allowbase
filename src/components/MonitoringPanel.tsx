import { AlertOctagon, AlertTriangle, Info, RefreshCw } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { getMonitoringSummary, type MonitoringAlert, type MonitoringSummary } from '../services/monitoringService';
import { chartPalette, useTheme } from '../theme';

const RANGES = [
  { label: '1h', hours: 1 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
  { label: '30d', hours: 720 },
];

const alertStyle: Record<MonitoringAlert['severity'], { cls: string; icon: typeof Info }> = {
  critical: { cls: 'border-rose-400/40 bg-rose-400/10 text-rose-300', icon: AlertOctagon },
  warning: { cls: 'border-amber-400/40 bg-amber-400/10 text-amber-300', icon: AlertTriangle },
  info: { cls: 'border-sky-400/30 bg-sky-400/10 text-sky-300', icon: Info },
};

function pct(value: number): string {
  return `${(value * 100).toFixed(value < 0.1 ? 1 : 0)}%`;
}

function ms(value: number | null): string {
  if (value === null || value === undefined) return '—';
  return value >= 1000 ? `${(value / 1000).toFixed(1)}s` : `${Math.round(value)}ms`;
}

function usd(value: number): string {
  if (value === 0) return '$0';
  return value < 0.01 ? `$${value.toFixed(4)}` : `$${value.toFixed(2)}`;
}

function Kpi({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: string }) {
  return (
    <div className="rounded-xl border border-line bg-ink-950/60 p-4">
      <p className="text-xs font-medium text-mist-500">{label}</p>
      <p className={`mt-1.5 text-2xl font-semibold tabular-nums ${tone ?? 'text-mist-100'}`}>{value}</p>
      {hint ? <p className="mt-1 text-[11px] text-mist-600">{hint}</p> : null}
    </div>
  );
}

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { name?: string; value?: number | string; color?: string }[];
  label?: string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded-xl border border-line bg-ink-950/95 px-3 py-2 text-xs shadow-panel">
      {label ? <p className="mb-1 font-semibold text-mist-200">{label}</p> : null}
      {payload.map((entry, index) => (
        <p key={`${entry.name ?? 'v'}-${index}`} className="text-mist-400">
          <span style={{ color: entry.color }}>●</span> {entry.name}: <span className="text-mist-100">{entry.value}</span>
        </p>
      ))}
    </div>
  );
}

/** Operational health: latency, errors, denials, rate limiting, cost, and alerts. */
export function MonitoringPanel() {
  const [hours, setHours] = useState(24);
  const [data, setData] = useState<MonitoringSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);
  const { theme } = useTheme();
  const palette = chartPalette[theme];

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    getMonitoringSummary(hours)
      .then((summary) => {
        if (!cancelled) setData(summary);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load monitoring data.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [hours, refreshKey]);

  const series = (data?.timeseries ?? []).map((point) => ({
    ...point,
    label: new Date(point.bucket).toLocaleString(undefined, hours > 48 ? { month: 'short', day: 'numeric' } : { hour: 'numeric' }),
  }));

  return (
    <section aria-labelledby="monitoring-heading" className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 id="monitoring-heading" className="text-xl font-semibold text-mist-100">
            Monitoring
          </h2>
          <p className="mt-1 text-sm text-mist-400">
            Latency, errors, denials and estimated spend across the gateway and ingest API.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div role="group" aria-label="Time range" className="flex rounded-lg border border-line p-0.5">
            {RANGES.map((range) => (
              <button
                key={range.hours}
                type="button"
                onClick={() => setHours(range.hours)}
                aria-pressed={hours === range.hours}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition ${
                  hours === range.hours ? 'bg-accent-500/15 text-accent-300' : 'text-mist-400 hover:text-mist-200'
                }`}
              >
                {range.label}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            aria-label="Refresh monitoring data"
            className="rounded-lg border border-line p-2 text-mist-400 transition hover:border-line-strong hover:text-mist-100"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : undefined} />
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-xl border border-rose-400/30 bg-ink-950/60 p-6">
          <p className="text-sm text-mist-300">{error}</p>
        </div>
      ) : !data && loading ? (
        <div className="rounded-xl border border-line bg-ink-950/60 p-6">
          <p className="text-sm text-mist-500">Loading monitoring data…</p>
        </div>
      ) : !data ? (
        <div className="rounded-xl border border-line bg-ink-950/60 p-6">
          <p className="text-sm text-mist-500">Sign in to see monitoring for your workspace.</p>
        </div>
      ) : (
        <>
          {data.alerts.length > 0 ? (
            <ul className="space-y-2" aria-label="Active alerts">
              {data.alerts.map((alert) => {
                const { cls, icon: Icon } = alertStyle[alert.severity];
                return (
                  <li key={alert.code} className={`flex items-start gap-2.5 rounded-xl border px-4 py-3 text-sm ${cls}`}>
                    <Icon size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
                    <span>
                      <span className="sr-only">{alert.severity}: </span>
                      {alert.message}
                    </span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="rounded-xl border border-mint-400/25 bg-mint-400/5 px-4 py-3 text-sm text-mint-300">
              All clear — no alerts in this window.
            </p>
          )}

          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Kpi label="Requests" value={data.totals.requests.toLocaleString()} hint={`${data.totals.fallbacks} used a fallback`} />
            <Kpi
              label="Error rate"
              value={pct(data.error_rate)}
              hint={`${data.totals.errors} errors`}
              tone={data.error_rate > 0.05 ? 'text-rose-300' : undefined}
            />
            <Kpi label="p95 latency" value={ms(data.latency.p95)} hint={`p50 ${ms(data.latency.p50)} · p99 ${ms(data.latency.p99)}`} />
            <Kpi label="Denial rate" value={pct(data.denial_rate)} hint={`${data.totals.blocked + data.totals.denied} blocked`} />
            <Kpi label="Rate limited" value={data.totals.rate_limited.toLocaleString()} hint={`${data.totals.output_redactions} outputs redacted`} />
            <Kpi
              label="Est. cost"
              value={usd(data.totals.cost_usd)}
              hint={`${(data.totals.input_tokens + data.totals.output_tokens).toLocaleString()} tokens`}
            />
          </div>

          {series.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line bg-ink-900/40 p-8 text-center">
              <p className="text-sm font-semibold text-mist-200">No traffic in this window.</p>
              <p className="mt-1 text-sm text-mist-500">
                Metrics appear once requests go through the AI gateway or the ingest API.
              </p>
            </div>
          ) : (
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-line bg-ink-950/60 p-5">
                <h3 className="text-sm font-semibold text-mist-200">Traffic and errors</h3>
                <div className="mt-4 h-60">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={series} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
                      <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
                      <XAxis dataKey="label" tick={{ fill: palette.tick, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: palette.tick, fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Area type="monotone" dataKey="requests" name="Requests" stroke={palette.area} fill={palette.area} fillOpacity={0.15} strokeWidth={2} />
                      <Area type="monotone" dataKey="errors" name="Errors" stroke={palette.blocked} fill={palette.blocked} fillOpacity={0.12} strokeWidth={1.5} />
                      <Area type="monotone" dataKey="rate_limited" name="Rate limited" stroke={palette.risk[1]} fill="transparent" strokeDasharray="4 4" strokeWidth={1.5} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
              <div className="rounded-xl border border-line bg-ink-950/60 p-5">
                <h3 className="text-sm font-semibold text-mist-200">p95 latency (ms)</h3>
                <div className="mt-4 h-60">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={series} margin={{ top: 8, right: 8, bottom: 0, left: -8 }}>
                      <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
                      <XAxis dataKey="label" tick={{ fill: palette.tick, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: palette.tick, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Line type="monotone" dataKey="p95_ms" name="p95 ms" stroke={palette.bar} strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          )}

          {data.providers.length > 0 ? (
            <div className="overflow-hidden rounded-xl border border-line bg-ink-950/60">
              <table className="w-full text-left text-sm">
                <caption className="sr-only">Per-provider breakdown</caption>
                <thead className="border-b border-line text-xs text-mist-500">
                  <tr>
                    <th scope="col" className="px-5 py-3 font-medium">Provider</th>
                    <th scope="col" className="px-5 py-3 text-right font-medium">Requests</th>
                    <th scope="col" className="px-5 py-3 text-right font-medium">Errors</th>
                    <th scope="col" className="px-5 py-3 text-right font-medium">Provider p95</th>
                    <th scope="col" className="px-5 py-3 text-right font-medium">Est. cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {data.providers.map((row) => (
                    <tr key={row.provider}>
                      <td className="px-5 py-3 font-medium text-mist-200">{row.provider}</td>
                      <td className="px-5 py-3 text-right tabular-nums text-mist-300">{row.requests.toLocaleString()}</td>
                      <td className={`px-5 py-3 text-right tabular-nums ${row.errors > 0 ? 'text-rose-300' : 'text-mist-300'}`}>
                        {row.errors.toLocaleString()}
                      </td>
                      <td className="px-5 py-3 text-right tabular-nums text-mist-300">{ms(row.p95_ms)}</td>
                      <td className="px-5 py-3 text-right tabular-nums text-mist-300">{usd(row.cost_usd)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          <p className="text-xs text-mist-600">
            Costs are list-price estimates from token usage; check provider invoices for billed amounts.
          </p>
        </>
      )}
    </section>
  );
}
