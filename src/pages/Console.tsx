import {
  Activity,
  ClipboardCheck,
  FlaskConical,
  Gauge,
  LayoutDashboard,
  Loader2,
  Plug,
  Settings,
  ShieldCheck,
  Users,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { Agents } from '../sections/Agents';
import { AIRequest } from '../sections/AIRequest';
import { Approvals } from '../sections/Approvals';
import { ApiKeys } from '../sections/ApiKeys';
import { DataSources } from '../sections/DataSources';
import { Requests } from '../sections/Requests';
import { PolicyEngine } from '../sections/PolicyEngine';
import { MembersPanel } from '../components/MembersPanel';
import { MonitoringPanel } from '../components/MonitoringPanel';
import { OrgSettingsPanel } from '../components/OrgSettingsPanel';
import { ProviderConnections } from '../components/ProviderConnections';
import { GatewayTest } from '../components/GatewayTest';
import { Dashboard } from '../components/Dashboard';
import { SetupModal } from '../components/SetupModal';
import { getActiveOrganizationId, getSupabase, isSupabaseConfigured } from '../lib/supabase';
import { getSetupStatusSafe, setupConnectComplete } from '../services/setupService';
import { getActiveOrganization, getMyOrganizationRole } from '../services/organizationService';
import { getAIRequests, type AIRequestRow } from '../services/aiRequestService';
import { listApprovals, type ApprovalItem } from '../services/approvalService';

interface ConsoleProps {
  onSimulate: () => void;
}

const tabs = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'connections', label: 'Connections', icon: Plug },
  { id: 'policies', label: 'Policies', icon: ShieldCheck },
  { id: 'events', label: 'Security Events', icon: Activity },
  { id: 'monitoring', label: 'Monitoring', icon: Gauge },
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

const riskCls: Record<string, string> = {
  critical: 'border-rose-400/30 bg-rose-400/10 text-rose-300',
  high: 'border-rose-400/30 bg-rose-400/10 text-rose-300',
  medium: 'border-amber-400/30 bg-amber-400/10 text-amber-300',
  low: 'border-mint-400/30 bg-mint-400/10 text-mint-300',
};

const statusCls: Record<string, string> = {
  blocked: 'border-rose-400/30 bg-rose-400/10 text-rose-300',
  allowed: 'border-mint-400/30 bg-mint-400/10 text-mint-300',
  in_review: 'border-amber-400/30 bg-amber-400/10 text-amber-300',
};

function DashboardTab({ onSimulate, goToTab }: { onSimulate: () => void; goToTab: (t: TabId) => void }) {
  const [events, setEvents] = useState<AIRequestRow[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState<ApprovalItem[]>([]);

  useEffect(() => {
    let cancelled = false;
    Promise.all([getAIRequests(5).catch(() => []), listApprovals().catch(() => [])]).then(
      ([reqs, approvals]) => {
        if (cancelled) return;
        setEvents(reqs);
        setPendingApprovals(approvals.filter((a) => a.status === 'pending'));
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div>
      <div className="mb-6 grid gap-3 sm:grid-cols-3">
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
            <span className="block text-sm font-semibold text-mist-100">
              Review approvals
              {pendingApprovals.length > 0 ? ` (${pendingApprovals.length})` : ''}
            </span>
            <span className="block text-xs text-mist-500">Requests waiting on a human.</span>
          </span>
        </button>
      </div>

      <Dashboard />

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-line bg-ink-950/60 p-5">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-mist-100">Recent security events</h3>
            <button
              type="button"
              onClick={() => goToTab('events')}
              className="text-xs font-medium text-accent-400 underline-offset-2 hover:underline"
            >
              View all
            </button>
          </div>
          <div className="mt-4 space-y-2">
            {events.length === 0 ? (
              <p className="text-sm text-mist-500">No requests yet — run the simulator.</p>
            ) : (
              events.map((event) => (
                <div
                  key={event.id}
                  className="flex items-center justify-between gap-3 rounded-xl border border-line bg-ink-900/60 px-3 py-2.5"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm text-mist-200">{event.purpose}</p>
                    <p className="text-[11px] text-mist-600">
                      {new Date(event.created_at).toLocaleString()}
                      {event.model ? ` · ${event.model}` : ''}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    <span
                      className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${riskCls[event.risk] ?? 'border-line text-mist-500'}`}
                    >
                      {event.risk}
                    </span>
                    <span
                      className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${statusCls[event.status] ?? 'border-line text-mist-500'}`}
                    >
                      {event.status.replace('_', ' ')}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="rounded-xl border border-line bg-ink-950/60 p-5">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-mist-100">Pending approvals</h3>
            <button
              type="button"
              onClick={() => goToTab('approvals')}
              className="text-xs font-medium text-accent-400 underline-offset-2 hover:underline"
            >
              Review
            </button>
          </div>
          <div className="mt-4 space-y-2">
            {pendingApprovals.length === 0 ? (
              <p className="text-sm text-mist-500">Nothing waiting — the queue is clear.</p>
            ) : (
              pendingApprovals.slice(0, 5).map((approval) => (
                <div
                  key={approval.id}
                  className="flex items-center justify-between gap-3 rounded-xl border border-amber-400/25 bg-amber-400/5 px-3 py-2.5"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm text-mist-200">{approval.request.purpose}</p>
                    <p className="text-[11px] text-mist-600">
                      {new Date(approval.created_at).toLocaleString()}
                    </p>
                  </div>
                  <span className="shrink-0 rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-[11px] font-medium text-amber-300">
                    pending
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
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
  /**
   * Setup gate: a signed-in user with an incomplete workspace connects
   * everything first (blocking wizard), then sees the dashboard.
   */
  const [gate, setGate] = useState<'checking' | 'needs-setup' | 'ready'>('checking');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (!isSupabaseConfigured()) return 'ready';
        const supabase = getSupabase();
        const {
          data: { session },
        } = await supabase!.auth.getSession();
        if (!session) return 'ready';
        if (window.sessionStorage.getItem('dcp-setup-skipped') === '1') return 'ready';
        const status = await getSetupStatusSafe().catch(() => null);
        return status && setupConnectComplete(status) ? 'ready' : 'needs-setup';
      } catch {
        return 'ready';
      }
    })().then((next) => {
      if (!cancelled) setGate(next);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  /** After the blocking wizard closes: re-check; a skip is remembered for this tab session. */
  const handleWizardDone = async () => {
    try {
      const status = await getSetupStatusSafe().catch(() => null);
      if (status && setupConnectComplete(status)) {
        setGate('ready');
        return;
      }
    } catch {
      /* fall through to skip */
    }
    try {
      window.sessionStorage.setItem('dcp-setup-skipped', '1');
    } catch {
      /* private mode — the gate just re-checks next visit */
    }
    setGate('ready');
  };

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

  if (gate === 'checking') {
    return (
      <div className="mx-auto flex min-h-[60vh] max-w-7xl items-center justify-center px-4 pt-24 sm:px-6 lg:px-8">
        <p className="flex items-center gap-2 text-sm text-mist-400">
          <Loader2 size={16} className="animate-spin" /> Checking your workspace…
        </p>
      </div>
    );
  }

  if (gate === 'needs-setup') {
    return (
      <div className="mx-auto min-h-[60vh] max-w-7xl px-4 pt-24 sm:px-6 lg:px-8">
        <SetupModal
          open
          blocking
          onClose={() => void handleWizardDone()}
          onSignIn={() => setGate('ready')}
          onTrySimulator={onSimulate}
        />
      </div>
    );
  }

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
              <ProviderConnections />
              <GatewayTest />
              <DataSources />
              <Agents />
              <ApiKeys />
            </div>
          )}
          {tab === 'policies' && <PolicyEngine />}
          {tab === 'events' && <Requests />}
          {tab === 'monitoring' && <MonitoringPanel />}
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
