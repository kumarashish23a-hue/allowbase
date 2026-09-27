import {
  Activity,
  ClipboardCheck,
  FlaskConical,
  LayoutDashboard,
  Loader2,
  Plug,
  Settings,
  ShieldCheck,
  Users,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Agents } from '../sections/Agents';
import { AIRequest } from '../sections/AIRequest';
import { Approvals } from '../sections/Approvals';
import { ApiKeys } from '../sections/ApiKeys';
import { DataSources } from '../sections/DataSources';
import { Requests } from '../sections/Requests';
import { PolicyEngine } from '../sections/PolicyEngine';
import { MembersPanel } from '../components/MembersPanel';
import { OrgSettingsPanel } from '../components/OrgSettingsPanel';
import { getActiveOrganizationId } from '../lib/supabase';
import { getActiveOrganization, getMyOrganizationRole } from '../services/organizationService';
import { getDashboard, type DashboardData } from '../services/dashboardService';
import type { Metric } from '../types';

interface ConsoleProps {
  onSimulate: () => void;
}

const tabs = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'connections', label: 'Connections', icon: Plug },
  { id: 'policies', label: 'Policies', icon: ShieldCheck },
  { id: 'events', label: 'Security Events', icon: Activity },
  { id: 'approvals', label: 'Approvals', icon: ClipboardCheck },
  { id: 'users', label: 'Users', icon: Users },
  { id: 'settings', label: 'Settings', icon: Settings },
] as const;

type TabId = (typeof tabs)[number]['id'];

/** Deep links from the setup wizard land on a tab instead of a hidden anchor. */
function tabForHash(hash: string): TabId | null {
  switch (hash) {
    case '#data-sources':
    case '#agents':
    case '#api-keys':
      return 'connections';
    case '#requests':
      return 'events';
    case '#policies':
      return 'policies';
    case '#approvals':
      return 'approvals';
    default:
      return null;
  }
}

const toneCls: Record<Metric['tone'], string> = {
  good: 'text-mint-300',
  bad: 'text-rose-300',
  warn: 'text-amber-300',
  neutral: 'text-mist-200',
};

function DashboardTab({ onSimulate, goToTab }: { onSimulate: () => void; goToTab: (t: TabId) => void }) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getDashboard('24h')
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load metrics.');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-mist-100">Security overview</h2>
        {data ? (
          <span
            className={`rounded-full border px-3 py-1 text-xs font-medium ${
              data.live
                ? 'border-mint-400/30 bg-mint-400/10 text-mint-300'
                : 'border-line bg-ink-900 text-mist-500'
            }`}
          >
            {data.live ? 'Live data' : 'Demo data'}
          </span>
        ) : null}
      </div>

      {error ? (
        <p className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-300">
          {error}
        </p>
      ) : !data ? (
        <p className="flex items-center gap-2 text-sm text-mist-500">
          <Loader2 size={14} className="animate-spin" /> Loading metrics…
        </p>
      ) : (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
          {data.metrics.map((metric) => (
            <div
              key={metric.label}
              className="rounded-xl border border-line bg-ink-950/60 px-4 py-3"
            >
              <p className={`text-2xl font-bold ${toneCls[metric.tone]}`}>{metric.value}</p>
              <p className="mt-1 text-xs font-medium text-mist-400">{metric.label}</p>
              <p className="text-[11px] text-mist-600">{metric.delta}</p>
            </div>
          ))}
        </div>
      )}

      <div className="mt-6 grid gap-3 sm:grid-cols-3">
        <button
          type="button"
          onClick={onSimulate}
          className="flex items-center gap-3 rounded-xl border border-line bg-ink-950/60 p-4 text-left transition hover:border-line-strong"
        >
          <FlaskConical size={18} className="shrink-0 text-accent-400" />
          <span>
            <span className="block text-sm font-semibold text-mist-100">Test a request</span>
            <span className="block text-xs text-mist-500">Run the simulator against live policies.</span>
          </span>
        </button>
        <button
          type="button"
          onClick={() => goToTab('connections')}
          className="flex items-center gap-3 rounded-xl border border-line bg-ink-950/60 p-4 text-left transition hover:border-line-strong"
        >
          <Plug size={18} className="shrink-0 text-accent-400" />
          <span>
            <span className="block text-sm font-semibold text-mist-100">Connect data</span>
            <span className="block text-xs text-mist-500">Sources, agents and API keys.</span>
          </span>
        </button>
        <button
          type="button"
          onClick={() => goToTab('approvals')}
          className="flex items-center gap-3 rounded-xl border border-line bg-ink-950/60 p-4 text-left transition hover:border-line-strong"
        >
          <ClipboardCheck size={18} className="shrink-0 text-accent-400" />
          <span>
            <span className="block text-sm font-semibold text-mist-100">Review approvals</span>
            <span className="block text-xs text-mist-500">Requests waiting on a human.</span>
          </span>
        </button>
      </div>

      <div className="mt-8">
        <AIRequest onSimulate={onSimulate} />
      </div>
    </div>
  );
}

/** The control panel: Dashboard, Connections, Policies, Events, Approvals, Users, Settings. */
export function Console({ onSimulate }: ConsoleProps) {
  const location = useLocation();
  const [tab, setTab] = useState<TabId>('dashboard');
  const [isAdmin, setIsAdmin] = useState(false);
  const [orgId, setOrgId] = useState<string | null>(null);
  const [orgName, setOrgName] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const id = await getActiveOrganizationId().catch(() => null);
      setOrgId(id);
      if (!id) return;
      const [role, org] = await Promise.all([
        getMyOrganizationRole(id).catch(() => null),
        getActiveOrganization().catch(() => null),
      ]);
      setIsAdmin(role === 'owner' || role === 'admin');
      setOrgName(org?.name ?? null);
    })();
  }, []);

  // Wizard deep links (#data-sources, #api-keys, …) open the matching tab.
  useEffect(() => {
    const next = tabForHash(location.hash);
    if (next) {
      setTab(next);
      window.scrollTo(0, 0);
    }
  }, [location.hash]);

  const goToTab = (next: TabId) => {
    setTab(next);
    window.scrollTo(0, 0);
  };

  return (
    <div className="mx-auto max-w-7xl px-4 pt-24 sm:px-6 lg:px-8 lg:pt-28">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-accent-600">Console</p>
          <h1 className="mt-3 max-w-2xl text-3xl font-bold tracking-tight text-mist-100 sm:text-4xl">
            Control panel{orgName ? ` — ${orgName}` : ''}.
          </h1>
          <p className="mt-3 max-w-2xl text-base leading-relaxed text-mist-400">
            Connect → configure → protect → monitor. Everything here reads from and writes to your
            Supabase project in real time.
          </p>
        </div>
        {isAdmin ? (
          <Link
            to="/admin"
            className="mt-1 inline-flex items-center gap-2 rounded-xl border border-line px-4 py-2.5 text-sm font-medium text-mist-200 transition hover:border-line-strong hover:text-mist-100"
          >
            <ShieldCheck size={15} /> Admin panel
          </Link>
        ) : null}
      </div>

      {/* Tab bar: horizontal scroll on mobile, sidebar on desktop */}
      <div className="mt-8 flex gap-8">
        <nav
          aria-label="Console sections"
          className="flex gap-1 overflow-x-auto pb-1 lg:sticky lg:top-24 lg:w-52 lg:shrink-0 lg:flex-col lg:gap-1 lg:self-start lg:overflow-visible lg:pb-0"
        >
          {tabs.map(({ id, label, icon: Icon }) => {
            const active = tab === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => goToTab(id)}
                aria-current={active ? 'page' : undefined}
                className={`flex shrink-0 items-center gap-2.5 rounded-xl px-3.5 py-2.5 text-sm font-medium transition ${
                  active
                    ? 'bg-accent-500/15 text-accent-300'
                    : 'text-mist-400 hover:bg-ink-900 hover:text-mist-200'
                }`}
              >
                <Icon size={16} className="shrink-0" />
                {label}
              </button>
            );
          })}
        </nav>

        <div className="min-w-0 flex-1">
          {tab === 'dashboard' && <DashboardTab onSimulate={onSimulate} goToTab={goToTab} />}
          {tab === 'connections' && (
            <div className="space-y-2">
              <DataSources />
              <Agents />
              <ApiKeys />
            </div>
          )}
          {tab === 'policies' && <PolicyEngine />}
          {tab === 'events' && <Requests />}
          {tab === 'approvals' && <Approvals />}
          {tab === 'users' && (
            <MembersPanel orgId={orgId} orgName={orgName} readOnly={!isAdmin} />
          )}
          {tab === 'settings' && <OrgSettingsPanel />}
        </div>
      </div>
    </div>
  );
}
