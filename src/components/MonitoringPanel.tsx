import { AlertTriangle, BellRing, Loader2, Plus } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { getActiveOrganizationId } from '../lib/supabase';
import { getMyOrganizationRole } from '../services/organizationService';
import {
  ALERT_METRIC_LABELS,
  createAlertRule,
  getAlertRules,
  getAlerts,
  getMetrics24h,
  summarizeMetrics,
  toggleAlertRule,
  type Alert,
  type AlertMetric,
  type AlertRule,
} from '../services/monitoringService';

const cardCls = 'rounded-xl border border-line bg-ink-950/60 p-5';
const inputCls =
  'mt-1.5 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none';
const secondaryBtn =
  'inline-flex items-center justify-center gap-2 rounded-xl border border-line px-4 py-2.5 text-sm font-semibold text-mist-200 transition hover:border-line-strong hover:text-mist-100 disabled:cursor-not-allowed disabled:opacity-60';
const primaryBtn =
  'inline-flex items-center justify-center gap-2 rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-accent-ink transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60';

const severityCls: Record<Alert['severity'], string> = {
  critical: 'border-accent-400/40 bg-accent-500/10 text-accent-300',
  warning: 'border-amber-400/30 bg-amber-400/10 text-amber-400',
  info: 'border-line bg-ink-900/60 text-mist-300',
};

function formatPct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-US');
}

/** Production monitoring: live invocation health, alert history, and alert rules. */
export function MonitoringPanel() {
  const [orgId, setOrgId] = useState<string | null>(null);
  const [canManage, setCanManage] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState({ total: 0, errors: 0, rateLimited: 0, errorRate: 0, denialRate: 0, p95LatencyMs: 0, providerFailures: 0 });
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);

  const [ruleName, setRuleName] = useState('');
  const [ruleMetric, setRuleMetric] = useState<AlertMetric>('error_rate');
  const [ruleThreshold, setRuleThreshold] = useState('0.05');
  const [ruleWindow, setRuleWindow] = useState('60');
  const [saving, setSaving] = useState(false);
  const [toggling, setToggling] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (id: string) => {
    const [metrics, alertRows, ruleRows] = await Promise.all([
      getMetrics24h(id).catch(() => null),
      getAlerts(id).catch(() => null),
      getAlertRules(id).catch(() => null),
    ]);
    if (metrics === null) throw new Error('Monitoring tables are not set up yet — run migration 022_monitoring.sql.');
    setSummary(summarizeMetrics(metrics));
    setAlerts(alertRows ?? []);
    setRules(ruleRows ?? []);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const id = await getActiveOrganizationId();
        setOrgId(id);
        if (!id) return;
        const role = await getMyOrganizationRole(id).catch(() => null);
        setCanManage(role === 'owner' || role === 'admin');
        await load(id);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Could not load monitoring data.');
      } finally {
        setLoading(false);
      }
    })();
  }, [load]);

  const handleCreateRule = async () => {
    if (!orgId || !ruleName.trim()) return;
    const threshold = Number(ruleThreshold);
    const windowMinutes = Number(ruleWindow);
    if (!Number.isFinite(threshold) || threshold < 0) {
      setError('Threshold must be a non-negative number.');
      return;
    }
    if (!Number.isInteger(windowMinutes) || windowMinutes <= 0) {
      setError('Window must be a positive whole number of minutes.');
      return;
    }
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const created = await createAlertRule(orgId, {
        name: ruleName.trim(),
        metric: ruleMetric,
        threshold,
        window_minutes: windowMinutes,
      });
      setRules((prev) => [created, ...prev]);
      setRuleName('');
      setRuleThreshold('0.05');
      setRuleWindow('60');
      setNotice(`Alert rule "${created.name}" created.`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Could not create the alert rule.');
    } finally {
      setSaving(false);
    }
  };

  const handleRefresh = async () => {
    if (!orgId || refreshing) return;
    setRefreshing(true);
    setError(null);
    try {
      await load(orgId);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Could not refresh monitoring data.');
    } finally {
      setRefreshing(false);
    }
  };

  const handleToggle = async (rule: AlertRule) => {    setToggling(rule.id);
    setError(null);
    setNotice(null);
    try {
      await toggleAlertRule(rule.id, !rule.is_active);
      setRules((prev) => prev.map((r) => (r.id === rule.id ? { ...r, is_active: !r.is_active } : r)));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Could not update the alert rule.');
    } finally {
      setToggling(null);
    }
  };

  if (loading) {
    return (
      <div className={`${cardCls} flex items-center gap-3 text-sm text-mist-400`} role="status">
        <Loader2 size={16} className="animate-spin" /> Loading monitoring data…
      </div>
    );
  }

  const cards = [
    { label: 'Error rate', value: formatPct(summary.errorRate), detail: `${summary.errors} errors / ${summary.total} calls (24h)` },
    { label: 'P95 latency', value: `${summary.p95LatencyMs.toLocaleString('en-US')} ms`, detail: '95th percentile invocation latency (24h)' },
    { label: 'Rate-limit denials', value: formatPct(summary.denialRate), detail: `${summary.rateLimited} denied by rate limiting (24h)` },
    { label: 'Provider failures', value: String(summary.providerFailures), detail: 'ai-gateway errors (24h)' },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-mist-100">Monitoring</h2>
          <p className="mt-1 text-sm text-mist-400">
            Invocation health for the edge functions over the last 24 hours, plus the alerts they trigger.
          </p>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={refreshing || !orgId}
          className={secondaryBtn}
        >
          {refreshing ? <Loader2 size={14} className="animate-spin" aria-hidden /> : null}
          Refresh
        </button>
      </div>

      {error && (
        <p role="alert" className="rounded-xl border border-accent-400/30 bg-accent-500/10 px-4 py-2.5 text-xs text-accent-300">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="rounded-xl border border-line bg-ink-900/60 px-4 py-2.5 text-xs text-mist-300">
          {notice}
        </p>
      )}

      {summary.total === 0 && !error && (
        <p className="rounded-xl border border-line bg-ink-900/60 px-4 py-2.5 text-xs text-mist-400">
          No invocations recorded in the last 24 hours. Metrics appear here once traffic flows through the
          instrumented edge functions.
        </p>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4" role="list" aria-label="Invocation health (last 24 hours)">
        {cards.map((card) => (
          <div key={card.label} role="listitem" className={cardCls}>
            <p className="text-xs font-medium uppercase tracking-wide text-mist-500">{card.label}</p>
            <p className="mt-2 text-2xl font-semibold text-mist-100">{card.value}</p>
            <p className="mt-1 text-xs text-mist-500">{card.detail}</p>
          </div>
        ))}
      </div>

      <section className={cardCls} aria-labelledby="alerts-heading">
        <div className="flex items-center gap-2">
          <BellRing size={16} className="text-accent-400" aria-hidden />
          <h3 id="alerts-heading" className="text-sm font-semibold text-mist-100">Recent alerts</h3>
        </div>
        {alerts.length === 0 ? (
          <p className="mt-3 text-sm text-mist-500">No alerts yet. Fired alerts will appear here with their severity.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {alerts.map((alert) => (
              <li key={alert.id} className="flex flex-wrap items-start gap-2 rounded-xl border border-line bg-ink-950/70 p-3">
                <span className={`inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${severityCls[alert.severity]}`}>
                  {alert.severity}
                </span>
                <span className={`inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${alert.status === 'firing' ? 'border-accent-400/40 bg-accent-500/10 text-accent-300' : 'border-line text-mist-400'}`}>
                  {alert.status}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-mist-200">{alert.message}</p>
                  <p className="mt-0.5 text-xs text-mist-500">
                    Fired {formatTime(alert.fired_at)}
                    {alert.resolved_at ? ` · Resolved ${formatTime(alert.resolved_at)}` : ''}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className={cardCls} aria-labelledby="rules-heading">
        <div className="flex items-center gap-2">
          <AlertTriangle size={16} className="text-accent-400" aria-hidden />
          <h3 id="rules-heading" className="text-sm font-semibold text-mist-100">Alert rules</h3>
        </div>
        {rules.length === 0 ? (
          <p className="mt-3 text-sm text-mist-500">
            No rules yet. Add one below — the monitoring check evaluates active rules over their trailing window.
          </p>
        ) : (
          <ul className="mt-3 space-y-2">
            {rules.map((rule) => (
              <li key={rule.id} className="flex flex-wrap items-center gap-3 rounded-xl border border-line bg-ink-950/70 p-3">
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-mist-100">{rule.name}</p>
                  <p className="mt-0.5 text-xs text-mist-500">
                    {ALERT_METRIC_LABELS[rule.metric]} · threshold {rule.threshold} · {rule.window_minutes} min window
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggle(rule)}
                  disabled={!canManage || toggling === rule.id}
                  aria-pressed={rule.is_active}
                  aria-label={`${rule.is_active ? 'Disable' : 'Enable'} rule ${rule.name}`}
                  title={canManage ? undefined : 'Only owners and admins can change rules'}
                  className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold transition disabled:cursor-not-allowed disabled:opacity-60 ${
                    rule.is_active
                      ? 'border-accent-400/40 bg-accent-500/10 text-accent-300'
                      : 'border-line text-mist-400 hover:text-mist-200'
                  }`}
                >
                  {toggling === rule.id ? <Loader2 size={12} className="animate-spin" /> : null}
                  {rule.is_active ? 'Active' : 'Paused'}
                </button>
              </li>
            ))}
          </ul>
        )}

        {canManage ? (
          <form
            className="mt-4 rounded-xl border border-line bg-ink-950/70 p-4"
            onSubmit={(e) => {
              e.preventDefault();
              void handleCreateRule();
            }}
          >
            <h4 className="text-sm font-semibold text-mist-100">New alert rule</h4>
            <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="rule-name" className="text-xs font-medium text-mist-300">Name</label>
                <input
                  id="rule-name"
                  type="text"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  placeholder="e.g. Gateway errors spiking"
                  maxLength={120}
                  required
                  className={inputCls}
                />
              </div>
              <div>
                <label htmlFor="rule-metric" className="text-xs font-medium text-mist-300">Metric</label>
                <select
                  id="rule-metric"
                  value={ruleMetric}
                  onChange={(e) => setRuleMetric(e.target.value as AlertMetric)}
                  className={inputCls}
                >
                  {(Object.keys(ALERT_METRIC_LABELS) as AlertMetric[]).map((metric) => (
                    <option key={metric} value={metric}>
                      {ALERT_METRIC_LABELS[metric]}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="rule-threshold" className="text-xs font-medium text-mist-300">
                  Threshold <span className="text-mist-500">(rate 0–1, latency/failures as a count)</span>
                </label>
                <input
                  id="rule-threshold"
                  type="number"
                  min="0"
                  step="any"
                  value={ruleThreshold}
                  onChange={(e) => setRuleThreshold(e.target.value)}
                  required
                  className={inputCls}
                />
              </div>
              <div>
                <label htmlFor="rule-window" className="text-xs font-medium text-mist-300">Window (minutes)</label>
                <input
                  id="rule-window"
                  type="number"
                  min="1"
                  step="1"
                  value={ruleWindow}
                  onChange={(e) => setRuleWindow(e.target.value)}
                  required
                  className={inputCls}
                />
              </div>
            </div>
            <button type="submit" disabled={saving || !ruleName.trim()} className={`${primaryBtn} mt-4`}>
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} aria-hidden />}
              Create rule
            </button>
          </form>
        ) : (
          <p className="mt-4 text-xs text-mist-500">Only workspace owners and admins can create or change alert rules.</p>
        )}
      </section>
    </div>
  );
}
