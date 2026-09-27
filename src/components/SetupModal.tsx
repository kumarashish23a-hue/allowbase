import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  ArrowRight,
  Bot,
  Building2,
  Check,
  CheckCircle2,
  Circle,
  Copy,
  Cpu,
  Database,
  Eye,
  ExternalLink,
  KeyRound,
  Loader2,
  RefreshCw,
  ShieldCheck,
  Table,
  Terminal,
} from 'lucide-react';
import { Modal } from './Modal';
import { getActiveOrganizationId } from '../lib/supabase';
import {
  createOrganization,
  setEnforcementMode,
  setOrgIndustry,
  type EnforcementMode,
} from '../services/organizationService';
import {
  EDGE_FUNCTION_NAME,
  INGEST_FUNCTION_NAME,
  getFunctionsDashboardUrl,
  getSetupStatus,
  getSqlEditorUrl,
  loadStarterData,
  probeEdgeFunction,
  type EdgeFunctionStatus,
  type SetupStatus,
} from '../services/setupService';

interface SetupModalProps {
  open: boolean;
  onClose: () => void;
  onSignIn: () => void;
  onTrySimulator: () => void;
}

const inputClass =
  'mt-3 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none';
const primaryBtn =
  'inline-flex items-center justify-center gap-2 rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-accent-ink transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60';
const secondaryBtn =
  'inline-flex items-center justify-center gap-2 rounded-xl border border-line px-4 py-2.5 text-sm font-semibold text-mist-200 transition hover:border-line-strong hover:text-mist-100 disabled:cursor-not-allowed disabled:opacity-60';

const STEP_TITLES = [
  'Organization',
  'Connect AI',
  'Connect data',
  'Connect apps & agents',
  'Security mode',
];

const AI_PROVIDERS = [
  { name: 'OpenAI', note: 'GPT models' },
  { name: 'Anthropic', note: 'Claude models' },
  { name: 'Google Gemini', note: 'Gemini models' },
  { name: 'Custom', note: 'Any OpenAI-compatible API' },
];

const DATA_CONNECTORS: { name: string; desc: string; status: 'implemented' | 'soon' }[] = [
  {
    name: 'PostgreSQL',
    desc: 'Discover schemas and classify tables. Metadata only — never reads row data.',
    status: 'implemented',
  },
  { name: 'Supabase', desc: 'Connect a Supabase Postgres database.', status: 'soon' },
  { name: 'Amazon S3', desc: 'Scan buckets and classify objects.', status: 'soon' },
  { name: 'Document upload', desc: 'Upload files for classification.', status: 'soon' },
  { name: 'REST API', desc: 'Pull metadata from any HTTP API.', status: 'soon' },
];

function stepDoneFlags(status: SetupStatus, modeConfirmed: boolean): boolean[] {
  return [
    status.hasOrg,
    status.models.length > 0,
    status.hasDataSource,
    status.hasAgent || status.hasApiKey,
    modeConfirmed,
  ];
}

function firstIncompleteOf(status: SetupStatus, modeConfirmed: boolean): number {
  const idx = stepDoneFlags(status, modeConfirmed).findIndex((done) => !done);
  return idx === -1 ? STEP_TITLES.length : idx;
}

export function SetupModal({ open, onClose, onSignIn, onTrySimulator }: SetupModalProps) {
  const navigate = useNavigate();
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [stepIndex, setStepIndex] = useState(0);
  const [orgName, setOrgName] = useState('');
  const [industry, setIndustry] = useState('');
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [savingIndustry, setSavingIndustry] = useState(false);
  const [editingIndustry, setEditingIndustry] = useState(false);
  const [loadingData, setLoadingData] = useState(false);
  const [probing, setProbing] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [modeConfirmed, setModeConfirmed] = useState(false);
  const [settingMode, setSettingMode] = useState(false);
  const [prereqFix, setPrereqFix] = useState<'db' | 'services' | null>(null);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const next = await getSetupStatus();
      setStatus(next);
      // Always land on the first unfinished step.
      setStepIndex((current) => {
        const first = firstIncompleteOf(next, modeConfirmedRef.current);
        // Keep the user's position if they deliberately navigated back.
        return current <= first ? current : first;
      });
    } catch {
      setError('Could not check your setup status. Try again.');
    } finally {
      setLoading(false);
    }
  };

  // modeConfirmed is read inside refresh's setState updater; keep a ref in sync.
  const modeConfirmedRef = useRef(false);

  useEffect(() => {
    if (!open) return;
    setCopiedCmd(null);
    setError(null);
    setPrereqFix(null);
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open ]);

  const handleCreateOrg = async () => {
    if (!orgName.trim()) {
      setError('Give your organization a name first.');
      return;
    }
    setCreatingOrg(true);
    setError(null);
    try {
      const orgId = await createOrganization(orgName.trim());
      if (industry.trim()) {
        await setOrgIndustry(orgId, industry.trim());
      }
      setOrgName('');
      setIndustry('');
      await refresh();
    } catch {
      setError('Could not create the organization. Try again.');
    } finally {
      setCreatingOrg(false);
    }
  };

  const handleSaveIndustry = async () => {
    if (!industry.trim()) {
      setError('Type an industry first, or leave it blank.');
      return;
    }
    setSavingIndustry(true);
    setError(null);
    try {
      const orgId = await getActiveOrganizationId();
      if (!orgId) throw new Error('No active organization.');
      await setOrgIndustry(orgId, industry.trim());
      setEditingIndustry(false);
      await refresh();
    } catch {
      setError('Could not save the industry. Try again.');
    } finally {
      setSavingIndustry(false);
    }
  };

  const handleLoadData = async () => {
    setLoadingData(true);
    setError(null);
    try {
      await loadStarterData();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load the starter workspace.');
    } finally {
      setLoadingData(false);
    }
  };

  const handleProbeFunctions = async () => {
    setProbing(true);
    setError(null);
    try {
      const [evaluate, ingest] = await Promise.all([
        probeEdgeFunction(EDGE_FUNCTION_NAME),
        probeEdgeFunction(INGEST_FUNCTION_NAME),
      ]);
      const functions = {
        'evaluate-ai-request': evaluate,
        'ingest-event': ingest,
      } as SetupStatus['functions'];
      setStatus((prev) => (prev ? { ...prev, functions } : prev));
    } catch {
      setError('Could not reach your Supabase project. Try again.');
    } finally {
      setProbing(false);
    }
  };

  const handleCopyCommand = async (command: string) => {
    setError(null);
    try {
      await navigator.clipboard.writeText(command);
      setCopiedCmd(command);
      window.setTimeout(() => setCopiedCmd((current) => (current === command ? null : current)), 2000);
    } catch {
      setError('Could not copy. Select the command text manually.');
    }
  };

  const handleChooseMode = async (mode: EnforcementMode) => {
    setSettingMode(true);
    setError(null);
    try {
      const orgId = await getActiveOrganizationId();
      if (!orgId) throw new Error('No active organization.');
      await setEnforcementMode(orgId, mode);
      modeConfirmedRef.current = true;
      setModeConfirmed(true);
      await refresh();
    } catch {
      setError('Could not change the security mode. Try again.');
    } finally {
      setSettingMode(false);
    }
  };

  const goToSection = (hash: string) => {
    onClose();
    navigate(`/app${hash}`);
  };

  const doneFlags = status ? stepDoneFlags(status, modeConfirmed) : [];
  const doneCount = doneFlags.filter(Boolean).length;
  const totalSteps = STEP_TITLES.length;
  const firstIncomplete = status ? firstIncompleteOf(status, modeConfirmed) : 0;
  const allDone = !!status && doneCount === totalSteps;
  const functionsUrl = getFunctionsDashboardUrl();
  const sqlEditorUrl = getSqlEditorUrl();
  const migrationsUrl = 'https://github.com/kumarashish23a-hue/dataplane/tree/main/supabase/migrations';

  const functionStatusLabel = (value: EdgeFunctionStatus) =>
    value === 'deployed' ? 'live' : value === 'missing' ? 'not deployed' : 'could not check';

  const goToStep = (index: number) => {
    if (!status) return;
    if (index < 0 || index > firstIncomplete) return;
    setStepIndex(index);
  };

  const bothFunctionsLive =
    !!status &&
    status.functions[EDGE_FUNCTION_NAME] === 'deployed' &&
    status.functions[INGEST_FUNCTION_NAME] === 'deployed';

  const renderDbFix = () => {
    if (!status) return null;
    if (status.migrations.state === 'ok') {
      return <p className="text-sm text-mist-400">All tables are in place.</p>;
    }
    if (status.migrations.state === 'missing') {
      return (
        <>
          <p className="text-sm text-mist-400">
            {status.migrations.missingFiles.length === 1 ? 'This file has' : 'These files have'} not
            been run yet:
          </p>
          <ul className="mt-2 space-y-2">
            {status.migrations.missingFiles.map((file) => (
              <li
                key={file}
                className="flex items-center gap-2 rounded-xl border border-line bg-ink-950/70 px-3 py-2 font-mono text-xs text-mist-200"
              >
                <Table size={14} className="shrink-0 text-accent-400" />
                supabase/migrations/{file}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-sm text-mist-400">
            Copy each file from{' '}
            <a
              href={migrationsUrl}
              target="_blank"
              rel="noreferrer"
              className="text-accent-400 underline-offset-2 hover:underline"
            >
              GitHub
            </a>
            , paste it into the SQL editor, and run it — in order.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {sqlEditorUrl && (
              <a
                href={sqlEditorUrl}
                target="_blank"
                rel="noreferrer"
                className={secondaryBtn}
              >
                <ExternalLink size={14} /> Open SQL editor
              </a>
            )}
            <button type="button" onClick={() => void refresh()} className={secondaryBtn}>
              <RefreshCw size={14} /> I've run them — check again
            </button>
          </div>
        </>
      );
    }
    return (
      <>
        <p className="text-sm text-mist-400">
          Could not check the database. Make sure you are signed in, then try again.
        </p>
        <button type="button" onClick={() => void refresh()} className={`${secondaryBtn} mt-3`}>
          <RefreshCw size={14} /> Check again
        </button>
      </>
    );
  };

  const renderServicesFix = () => {
    if (!status) return null;
    if (bothFunctionsLive) {
      return (
        <p className="text-sm text-mist-400">
          Both services are live — simulations run real policy evaluations and the API accepts
          events.
        </p>
      );
    }
    return (
      <>
        <p className="text-sm text-mist-400">
          These run inside your Supabase project. From your{' '}
          <span className="font-mono text-mist-200">dataplane</span> project folder, run:
        </p>
        <ul className="mt-2 space-y-2">
          {([EDGE_FUNCTION_NAME, INGEST_FUNCTION_NAME] as const).map((fn) => {
            const deployed = status.functions[fn] === 'deployed';
            const command = `npx supabase functions deploy ${fn}`;
            return (
              <li key={fn} className="rounded-xl border border-line bg-ink-950/70 px-3 py-2">
                <div className="flex items-center gap-2">
                  {deployed ? (
                    <CheckCircle2 size={14} className="shrink-0 text-mint-400" />
                  ) : (
                    <Circle size={14} className="shrink-0 text-mist-600" />
                  )}
                  <span className="font-mono text-xs text-mist-200">{fn}</span>
                  <span className="text-xs text-mist-500">
                    {functionStatusLabel(status.functions[fn])}
                  </span>
                </div>
                {!deployed && (
                  <button
                    type="button"
                    onClick={() => void handleCopyCommand(command)}
                    className="mt-2 flex w-full items-center justify-between gap-2 rounded-lg bg-ink-900 px-3 py-2 font-mono text-xs text-mist-300 transition hover:text-mist-100"
                  >
                    <span className="truncate">{command}</span>
                    {copiedCmd === command ? (
                      <Check size={14} className="shrink-0 text-mint-400" />
                    ) : (
                      <Copy size={14} className="shrink-0" />
                    )}
                  </button>
                )}
              </li>
            );
          })}
        </ul>
        <button
          type="button"
          onClick={() => void handleProbeFunctions()}
          disabled={probing}
          className={`${primaryBtn} mt-3 w-full`}
        >
          {probing ? <Loader2 size={15} className="animate-spin" /> : <RefreshCw size={15} />}
          {probing ? 'Checking…' : "I've deployed them — check again"}
        </button>
        {functionsUrl && (
          <a
            href={functionsUrl}
            target="_blank"
            rel="noreferrer"
            className="mt-2 inline-flex items-center gap-1.5 text-xs text-mist-500 transition hover:text-mist-300"
          >
            <ExternalLink size={13} /> or deploy in the dashboard
          </a>
        )}
        <p className="mt-2 flex items-start gap-1.5 text-xs text-mist-500">
          <Terminal size={13} className="mt-0.5 shrink-0" />
          Make sure the Supabase CLI is linked to this project first.
        </p>
      </>
    );
  };

  const renderPrereqs = () => {
    if (!status || !status.signedIn) return null;
    const pills: { key: 'db' | 'services'; label: string; ok: boolean }[] = [
      { key: 'db', label: 'Database', ok: status.migrations.state === 'ok' },
      { key: 'services', label: 'Services', ok: bothFunctionsLive },
    ];
    const anyBad = pills.some((p) => !p.ok);
    return (
      <div className="mb-5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-mint-400/30 bg-mint-400/10 px-3 py-1 text-xs font-medium text-mint-300">
            <Check size={12} /> Signed in
          </span>
          {pills.map((pill) => (
            <button
              key={pill.key}
              type="button"
              onClick={() => setPrereqFix((current) => (current === pill.key ? null : pill.key))}
              className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition ${
                pill.ok
                  ? 'border-mint-400/30 bg-mint-400/10 text-mint-300'
                  : 'border-amber-400/40 bg-amber-400/10 text-amber-300 hover:border-amber-400/70'
              }`}
            >
              {pill.ok ? <Check size={12} /> : <RefreshCw size={12} />}
              {pill.label}: {pill.ok ? 'ready' : 'needs attention'}
            </button>
          ))}
        </div>
        {anyBad && prereqFix === null && (
          <p className="mt-2 text-xs text-mist-500">
            Tap a highlighted pill above to fix it. The steps below still work meanwhile.
          </p>
        )}
        {prereqFix !== null && (
          <div className="mt-3 rounded-2xl border border-line bg-ink-950/60 p-4">
            {prereqFix === 'db' ? renderDbFix() : renderServicesFix()}
          </div>
        )}
      </div>
    );
  };

  const renderStepBody = () => {
    if (!status) return null;
    switch (stepIndex) {
      case 0:
        return (
          <>
            {status.hasOrg ? (
              <>
                <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                  Using{' '}
                  <span className="font-semibold text-mist-200">
                    {status.orgName ?? 'your organization'}
                  </span>
                  .
                </p>
                {status.industry && !editingIndustry ? (
                  <p className="mt-2 text-sm text-mist-400">
                    Industry: <span className="text-mist-200">{status.industry}</span>{' '}
                    <button
                      type="button"
                      onClick={() => {
                        setIndustry(status.industry ?? '');
                        setEditingIndustry(true);
                      }}
                      className="text-accent-400 underline-offset-2 hover:underline"
                    >
                      Change
                    </button>
                  </p>
                ) : (
                  <>
                    <input
                      value={industry}
                      onChange={(e) => setIndustry(e.target.value)}
                      placeholder="Industry (optional) — e.g. Healthcare"
                      disabled={savingIndustry}
                      aria-label="Industry"
                      className={inputClass}
                    />
                    <button
                      type="button"
                      disabled={savingIndustry}
                      onClick={() => void handleSaveIndustry()}
                      className={`${secondaryBtn} mt-3`}
                    >
                      {savingIndustry ? <Loader2 size={15} className="animate-spin" /> : null}
                      {savingIndustry ? 'Saving…' : 'Save industry'}
                    </button>
                  </>
                )}
              </>
            ) : (
              <>
                <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                  Everything lives inside an organization. You will be its owner.
                </p>
                <input
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="e.g. Acme Inc."
                  disabled={!status.signedIn || creatingOrg}
                  aria-label="Organization name"
                  className={inputClass}
                />
                <input
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                  placeholder="Industry (optional) — e.g. Healthcare"
                  disabled={!status.signedIn || creatingOrg}
                  aria-label="Industry"
                  className={inputClass}
                />
                <button
                  type="button"
                  disabled={!status.signedIn || creatingOrg}
                  onClick={() => void handleCreateOrg()}
                  className={`${primaryBtn} mt-4 w-full !py-3 !text-base`}
                >
                  {creatingOrg ? <Loader2 size={16} className="animate-spin" /> : <Building2 size={16} />}
                  {creatingOrg ? 'Creating…' : 'Create organization'}
                </button>
              </>
            )}
          </>
        );
      case 1:
        return (
          <>
            <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
              Which AI providers may your workspace use? Provider API keys are stored server-side
              only — that part arrives in the next update. For now, register the AI destinations
              your policies target.
            </p>
            <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {AI_PROVIDERS.map((provider) => (
                <div
                  key={provider.name}
                  className="flex items-center justify-between gap-2 rounded-xl border border-line bg-ink-950/60 px-3 py-2.5"
                >
                  <div>
                    <p className="text-sm font-medium text-mist-200">{provider.name}</p>
                    <p className="text-xs text-mist-500">{provider.note}</p>
                  </div>
                  <span
                    className="shrink-0 rounded-full border border-line bg-ink-900 px-2 py-0.5 text-[11px] font-medium text-mist-500"
                    title="Provider key storage arrives in the next update"
                  >
                    Not configured
                  </span>
                </div>
              ))}
            </div>
            <h4 className="mt-5 text-sm font-semibold text-mist-200">Registered AI models</h4>
            {status.models.length > 0 ? (
              <ul className="mt-2 space-y-2">
                {status.models.map((model) => (
                  <li
                    key={`${model.name}-${model.provider ?? ''}`}
                    className="flex items-center gap-2 rounded-xl border border-line bg-ink-950/60 px-3 py-2.5"
                  >
                    <Cpu size={15} className="shrink-0 text-accent-400" />
                    <span className="text-sm text-mist-200">{model.name}</span>
                    {model.provider && (
                      <span className="text-xs text-mist-500">{model.provider}</span>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-sm leading-relaxed text-mist-400">
                No AI models registered yet. The starter workspace adds two, or register your own in
                the console.
              </p>
            )}
          </>
        );
      case 2:
        return (
          <>
            <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
              Connect the data your AI is allowed to touch. PostgreSQL is live today — the rest are
              clearly marked until they are built.
            </p>
            <div className="mt-4 space-y-2">
              {DATA_CONNECTORS.map((connector) => (
                <div
                  key={connector.name}
                  className="flex items-center justify-between gap-3 rounded-xl border border-line bg-ink-950/60 px-3 py-2.5"
                >
                  <div className="flex items-start gap-2">
                    <Database size={15} className="mt-0.5 shrink-0 text-accent-400" />
                    <div>
                      <p className="text-sm font-medium text-mist-200">{connector.name}</p>
                      <p className="text-xs text-mist-500">{connector.desc}</p>
                    </div>
                  </div>
                  {connector.status === 'implemented' ? (
                    <button
                      type="button"
                      onClick={() => goToSection('#data-sources')}
                      className={`${secondaryBtn} shrink-0 !px-3 !py-1.5 !text-xs`}
                    >
                      Connect
                    </button>
                  ) : (
                    <span className="shrink-0 rounded-full border border-line bg-ink-900 px-2 py-0.5 text-[11px] font-medium text-mist-500">
                      Not configured
                    </span>
                  )}
                </div>
              ))}
            </div>
            {!status.hasDataSource && (
              <>
                <p className="mt-4 text-sm leading-relaxed text-mist-400">
                  Just exploring? The starter workspace adds demo sources, assets, models, an agent
                  and policies. Nothing is overwritten.
                </p>
                <button
                  type="button"
                  disabled={!status.hasOrg || loadingData}
                  onClick={() => void handleLoadData()}
                  className={`${primaryBtn} mt-3 w-full !py-3 !text-base`}
                >
                  {loadingData ? <Loader2 size={16} className="animate-spin" /> : <Database size={16} />}
                  {loadingData ? 'Loading…' : 'Load starter workspace'}
                </button>
              </>
            )}
          </>
        );
      case 3: {
        const cards = [
          {
            key: 'agents',
            icon: <Bot size={15} className="shrink-0 text-accent-400" />,
            title: 'Agents',
            desc: status.hasAgent
              ? 'At least one agent is registered and governed by policy.'
              : 'Register the AI agents or apps that will call through the control plane.',
            cta: 'Manage agents',
            hash: '#agents',
          },
          {
            key: 'keys',
            icon: <KeyRound size={15} className="shrink-0 text-accent-400" />,
            title: 'API keys',
            desc: status.hasApiKey
              ? 'You have an active API key for sending AI events.'
              : 'Your backend uses a key to send AI events here. It is shown once — store it somewhere safe.',
            cta: status.hasApiKey ? 'Manage keys' : 'Create API key',
            hash: '#api-keys',
          },
        ];
        return (
          <>
            <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
              Either one connects your application: an agent entry, an API key, or both.
            </p>
            <div className="mt-4 space-y-2">
              {cards.map((card) => (
                <div
                  key={card.key}
                  className="flex items-center justify-between gap-3 rounded-xl border border-line bg-ink-950/60 px-3 py-2.5"
                >
                  <div className="flex items-start gap-2">
                    {card.icon}
                    <div>
                      <p className="text-sm font-medium text-mist-200">{card.title}</p>
                      <p className="text-xs text-mist-500">{card.desc}</p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => goToSection(card.hash)}
                    disabled={!status.hasOrg}
                    className={`${secondaryBtn} shrink-0 !px-3 !py-1.5 !text-xs`}
                  >
                    {card.cta}
                  </button>
                </div>
              ))}
            </div>
          </>
        );
      }
      case 4: {
        const current = status.enforcementMode;
        const modes: { mode: EnforcementMode; icon: ReactNode; title: string; desc: string }[] = [
          {
            mode: 'monitor',
            icon: <Eye size={16} className="text-accent-400" />,
            title: 'Monitor',
            desc: 'Policies are evaluated and every decision is logged, but nothing is blocked. Start here to see what would happen.',
          },
          {
            mode: 'enforce',
            icon: <ShieldCheck size={16} className="text-accent-400" />,
            title: 'Enforce',
            desc: 'Policies are enforced: risky requests are blocked or held for approval.',
          },
        ];
        return (
          <>
            <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
              New workspaces start in <span className="text-mist-200">Monitor</span>. Pick the mode
              that fits right now — switching never deletes data.
            </p>
            <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {modes.map(({ mode, icon, title, desc }) => {
                const selected = current === mode;
                return (
                  <button
                    key={mode}
                    type="button"
                    disabled={!status.hasOrg || settingMode}
                    onClick={() => void handleChooseMode(mode)}
                    aria-pressed={selected}
                    className={`rounded-xl border p-4 text-left transition ${
                      selected
                        ? 'border-accent-400/60 bg-accent-500/10'
                        : 'border-line bg-ink-950/60 hover:border-line-strong'
                    } disabled:cursor-not-allowed disabled:opacity-60`}
                  >
                    <span className="flex items-center gap-2">
                      {icon}
                      <span className="text-sm font-semibold text-mist-100">{title}</span>
                      {selected && <Check size={14} className="text-mint-300" />}
                    </span>
                    <span className="mt-1.5 block text-xs leading-relaxed text-mist-400">{desc}</span>
                  </button>
                );
              })}
            </div>
            {settingMode && (
              <p className="mt-3 flex items-center gap-2 text-sm text-mist-400">
                <Loader2 size={14} className="animate-spin" /> Saving…
              </p>
            )}
          </>
        );
      }
      default:
        return null;
    }
  };

  const stepDone = status ? doneFlags[stepIndex] : false;
  const subtitle = allDone
    ? 'All done — nice work.'
    : status
      ? `Step ${Math.min(stepIndex + 1, totalSteps)} of ${totalSteps}`
      : 'Connect, configure, protect, monitor.';

  return (
    <Modal open={open} onClose={onClose} title="Workspace setup" subtitle={subtitle}>
      {loading || !status ? (
        <div className="flex items-center justify-center gap-2 py-10 text-sm text-mist-400">
          <Loader2 size={16} className="animate-spin" /> Checking your setup…
        </div>
      ) : !status.signedIn ? (
        <div>
          <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
            You need an account before anything else works.
          </p>
          <button
            type="button"
            onClick={() => {
              onClose();
              onSignIn();
            }}
            className={`${primaryBtn} mt-5 w-full !py-3 !text-base`}
          >
            Sign in
          </button>
        </div>
      ) : (
        <div>
          {renderPrereqs()}
          {/* Step dots */}
          <div className="flex items-center justify-center gap-2" role="tablist" aria-label="Setup steps">
            {STEP_TITLES.map((title, index) => {
              const done = doneFlags[index];
              const isCurrent = index === stepIndex && !allDone;
              const reachable = index <= firstIncomplete;
              return (
                <button
                  key={title}
                  type="button"
                  role="tab"
                  aria-selected={isCurrent}
                  aria-label={`${title}${done ? ' (done)' : ''}`}
                  title={title}
                  disabled={!reachable}
                  onClick={() => goToStep(index)}
                  className={`flex h-8 w-8 items-center justify-center rounded-full border text-xs font-semibold transition ${
                    done
                      ? 'border-mint-400/40 bg-mint-400/15 text-mint-300'
                      : isCurrent
                        ? 'border-accent-400/60 bg-accent-500/15 text-accent-300'
                        : 'border-line text-mist-500'
                  } ${reachable ? 'cursor-pointer hover:border-line-strong' : 'cursor-not-allowed opacity-50'}`}
                >
                  {done ? <Check size={14} /> : <span>{index + 1}</span>}
                </button>
              );
            })}
          </div>

          {allDone ? (
            <div className="mt-6 rounded-2xl border border-mint-400/30 bg-mint-400/10 p-6 text-center">
              <CheckCircle2 size={36} className="mx-auto text-mint-300" />
              <p className="mt-3 text-lg font-semibold text-mist-100">
                You're all set — the control plane is live.
              </p>
              <p className="mt-1 text-sm text-mist-400">
                Connect → configure → protect → monitor. Every AI call is now on the record.
              </p>
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onTrySimulator();
                }}
                className={`${primaryBtn} mt-5 w-full !py-3 !text-base`}
              >
                Try the simulator
              </button>
            </div>
          ) : (
            <div className="mt-6">
              <h3 className="text-xl font-semibold text-mist-100">{STEP_TITLES[stepIndex]}</h3>
              {renderStepBody()}
              {error ? <p className="mt-4 text-sm text-rose-400">{error}</p> : null}
              <div className="mt-6 flex items-center justify-between border-t border-line pt-4">
                <button
                  type="button"
                  onClick={() => goToStep(stepIndex - 1)}
                  disabled={stepIndex === 0}
                  className={`${secondaryBtn} !px-4 disabled:opacity-40`}
                >
                  <ArrowLeft size={15} /> Back
                </button>
                {stepDone && stepIndex < totalSteps - 1 ? (
                  <button
                    type="button"
                    onClick={() => goToStep(stepIndex + 1)}
                    className={`${primaryBtn} !px-5`}
                  >
                    Continue <ArrowRight size={15} />
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => void refresh()}
                    className={`${secondaryBtn} !px-4`}
                  >
                    <RefreshCw size={15} /> Re-check
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
