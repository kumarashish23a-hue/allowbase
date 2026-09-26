import { useEffect, useState } from 'react';
import {
  Activity,
  Building2,
  CheckCircle2,
  Circle,
  Copy,
  Database,
  ExternalLink,
  KeyRound,
  Loader2,
  RefreshCw,
  Table,
  Terminal,
  Zap,
} from 'lucide-react';
import { Modal } from './Modal';
import { createOrganization } from '../services/organizationService';
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
  'mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none';
const primaryBtn =
  'inline-flex items-center justify-center gap-2 rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-accent-ink transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60';
const secondaryBtn =
  'inline-flex items-center justify-center gap-2 rounded-xl border border-line px-4 py-2.5 text-sm font-semibold text-mist-200 transition hover:border-line-strong hover:text-mist-100 disabled:cursor-not-allowed disabled:opacity-60';

function StepIcon({ done, pending }: { done: boolean; pending?: boolean }) {
  if (done) return <CheckCircle2 size={20} className="shrink-0 text-mint-400" />;
  if (pending) return <Loader2 size={20} className="shrink-0 animate-spin text-accent-400" />;
  return <Circle size={20} className="shrink-0 text-mist-600" />;
}

export function SetupModal({ open, onClose, onSignIn, onTrySimulator }: SetupModalProps) {
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [orgName, setOrgName] = useState('');
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [loadingData, setLoadingData] = useState(false);
  const [probing, setProbing] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      setStatus(await getSetupStatus());
    } catch {
      setError('Could not check your setup status. Try again.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!open) return;
    setCopiedCmd(null);
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
      await createOrganization(orgName.trim());
      setOrgName('');
      await refresh();
    } catch {
      setError('Could not create the organization. Try again.');
    } finally {
      setCreatingOrg(false);
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
      setStatus((prev) =>
        prev ? { ...prev, functions: { 'evaluate-ai-request': evaluate, 'ingest-event': ingest } } : prev,
      );
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

  const goToApiKeys = () => {
    onClose();
    // Let the modal finish closing before scrolling.
    window.setTimeout(() => {
      document.getElementById('api-keys')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 150);
  };

  const doneCount = status
    ? [
        status.signedIn,
        status.hasOrg,
        status.migrations.state === 'ok',
        status.hasData,
        status.functions['evaluate-ai-request'] === 'deployed' &&
          status.functions['ingest-event'] === 'deployed',
        status.hasApiKey,
        status.hasRequests,
      ].filter(Boolean).length
    : 0;
  const totalSteps = 7;
  const allDone = !!status && doneCount === totalSteps;
  const functionsUrl = getFunctionsDashboardUrl();
  const sqlEditorUrl = getSqlEditorUrl();
  const migrationsUrl = 'https://github.com/kumarashish23a-hue/dataplane/tree/main/supabase/migrations';

  const functionStatusLabel = (value: EdgeFunctionStatus) =>
    value === 'deployed' ? 'live' : value === 'missing' ? 'not deployed' : 'could not check';

  return (
    <Modal open={open} onClose={onClose} title="Workspace setup" subtitle="From sign-in to your first live AI request.">
      {loading || !status ? (
        <div className="flex items-center justify-center gap-2 py-10 text-sm text-mist-400">
          <Loader2 size={16} className="animate-spin" /> Checking your setup…
        </div>
      ) : (
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between text-xs font-medium text-mist-400">
              <span>
                {doneCount} of {totalSteps} complete
              </span>
              <button
                type="button"
                onClick={() => void refresh()}
                className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1 text-mist-300 transition hover:text-mist-100"
              >
                <RefreshCw size={12} /> Re-check
              </button>
            </div>
            <div
              className="mt-2 h-1.5 overflow-hidden rounded-full bg-ink-800"
              role="progressbar"
              aria-valuenow={doneCount}
              aria-valuemin={0}
              aria-valuemax={totalSteps}
            >
              <div
                className="h-full rounded-full bg-mint-400 transition-all"
                style={{ width: `${(doneCount / totalSteps) * 100}%` }}
              />
            </div>
          </div>
          {/* Step 1 — Sign in */}
          <div className="rounded-xl border border-line bg-ink-900/60 p-4">
            <div className="flex items-start gap-3">
              <StepIcon done={status.signedIn} />
              <div className="flex-1">
                <p className="text-sm font-semibold text-mist-100">1. Sign in</p>
                <p className="mt-1 text-sm text-mist-400">
                  {status.signedIn ? 'You are signed in.' : 'You need an account before anything else works.'}
                </p>
                {!status.signedIn && (
                  <button
                    type="button"
                    onClick={() => {
                      onClose();
                      onSignIn();
                    }}
                    className={`${primaryBtn} mt-3`}
                  >
                    Sign in
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Step 2 — Organization */}
          <div className="rounded-xl border border-line bg-ink-900/60 p-4">
            <div className="flex items-start gap-3">
              <StepIcon done={status.hasOrg} pending={creatingOrg} />
              <div className="flex-1">
                <p className="text-sm font-semibold text-mist-100">2. Create your organization</p>
                {status.hasOrg ? (
                  <p className="mt-1 text-sm text-mist-400">
                    Using <span className="font-semibold text-mist-200">{status.orgName ?? 'your organization'}</span>.
                  </p>
                ) : (
                  <>
                    <p className="mt-1 text-sm text-mist-400">
                      Everything in the product lives inside an organization. You will be its owner.
                    </p>
                    <input
                      value={orgName}
                      onChange={(e) => setOrgName(e.target.value)}
                      placeholder="e.g. Acme Inc."
                      disabled={!status.signedIn || creatingOrg}
                      className={inputClass}
                    />
                    <button
                      type="button"
                      disabled={!status.signedIn || creatingOrg}
                      onClick={() => void handleCreateOrg()}
                      className={`${primaryBtn} mt-3`}
                    >
                      {creatingOrg ? <Loader2 size={15} className="animate-spin" /> : <Building2 size={15} />}
                      {creatingOrg ? 'Creating…' : 'Create organization'}
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Step 3 — Migrations */}
          <div className="rounded-xl border border-line bg-ink-900/60 p-4">
            <div className="flex items-start gap-3">
              <StepIcon done={status.migrations.state === 'ok'} />
              <div className="flex-1">
                <p className="text-sm font-semibold text-mist-100">3. Run the database migrations</p>
                {status.migrations.state === 'ok' ? (
                  <p className="mt-1 text-sm text-mist-400">All tables are in place.</p>
                ) : status.migrations.state === 'missing' ? (
                  <>
                    <p className="mt-1 text-sm text-mist-400">
                      These migrations have not been applied yet:
                    </p>
                    <ul className="mt-2 space-y-1.5">
                      {status.migrations.missingFiles.map((file) => (
                        <li
                          key={file}
                          className="inline-flex items-center gap-2 rounded-lg border border-line bg-ink-950/70 px-2.5 py-1 font-mono text-xs text-mist-200"
                        >
                          <Table size={13} className="text-accent-400" />
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
                          className={`${secondaryBtn} !px-3 !py-1.5 !text-xs`}
                        >
                          <ExternalLink size={13} /> Open SQL editor
                        </a>
                      )}
                      <button
                        type="button"
                        onClick={() => void refresh()}
                        className={`${secondaryBtn} !px-3 !py-1.5 !text-xs`}
                      >
                        <RefreshCw size={13} /> Check again
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <p className="mt-1 text-sm text-mist-400">
                      Could not check the database. Make sure you are signed in, then try again.
                    </p>
                    <button
                      type="button"
                      onClick={() => void refresh()}
                      className={`${secondaryBtn} mt-3 !px-3 !py-1.5 !text-xs`}
                    >
                      <RefreshCw size={13} /> Check again
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Step 4 — Starter data */}
          <div className="rounded-xl border border-line bg-ink-900/60 p-4">
            <div className="flex items-start gap-3">
              <StepIcon done={status.hasData} pending={loadingData} />
              <div className="flex-1">
                <p className="text-sm font-semibold text-mist-100">4. Load a starter workspace</p>
                {status.hasData ? (
                  <p className="mt-1 text-sm text-mist-400">Your workspace already has data.</p>
                ) : (
                  <>
                    <p className="mt-1 text-sm text-mist-400">
                      Adds 2 data sources, 2 data assets, 2 AI models, 1 agent, 2 policies and 1 finding —
                      everything the simulator needs. Nothing is overwritten.
                    </p>
                    <button
                      type="button"
                      disabled={!status.hasOrg || loadingData}
                      onClick={() => void handleLoadData()}
                      className={`${primaryBtn} mt-3`}
                    >
                      {loadingData ? <Loader2 size={15} className="animate-spin" /> : <Database size={15} />}
                      {loadingData ? 'Loading…' : 'Load starter workspace'}
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Step 5 — Edge functions */}
          <div className="rounded-xl border border-line bg-ink-900/60 p-4">
            <div className="flex items-start gap-3">
              <StepIcon
                done={
                  status.functions[EDGE_FUNCTION_NAME] === 'deployed' &&
                  status.functions[INGEST_FUNCTION_NAME] === 'deployed'
                }
                pending={probing}
              />
              <div className="flex-1">
                <p className="text-sm font-semibold text-mist-100">5. Deploy the edge functions</p>
                {status.functions[EDGE_FUNCTION_NAME] === 'deployed' &&
                status.functions[INGEST_FUNCTION_NAME] === 'deployed' ? (
                  <p className="mt-1 text-sm text-mist-400">
                    Both services are live — simulations run real policy evaluations and the API
                    accepts events.
                  </p>
                ) : (
                  <>
                    <p className="mt-1 text-sm text-mist-400">
                      These run inside your Supabase project. Deploy the missing ones from your{' '}
                      <span className="font-mono text-mist-200">dataplane</span> project folder:
                    </p>
                    <ul className="mt-2 space-y-2">
                      {([EDGE_FUNCTION_NAME, INGEST_FUNCTION_NAME] as const).map((fn) => {
                        const deployed = status.functions[fn] === 'deployed';
                        const command = `npx supabase functions deploy ${fn}`;
                        return (
                          <li
                            key={fn}
                            className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-ink-950/70 px-2.5 py-2"
                          >
                            <StepIcon done={deployed} />
                            <span className="font-mono text-xs text-mist-200">{fn}</span>
                            <span className="text-xs text-mist-500">
                              {functionStatusLabel(status.functions[fn])}
                            </span>
                            {!deployed && (
                              <button
                                type="button"
                                onClick={() => void handleCopyCommand(command)}
                                className={`${secondaryBtn} ml-auto !px-3 !py-1.5 !text-xs`}
                              >
                                {copiedCmd === command ? (
                                  <CheckCircle2 size={13} className="text-mint-400" />
                                ) : (
                                  <Copy size={13} />
                                )}
                                {copiedCmd === command ? 'Copied!' : 'Copy deploy command'}
                              </button>
                            )}
                          </li>
                        );
                      })}
                    </ul>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => void handleProbeFunctions()}
                        disabled={probing}
                        className={`${secondaryBtn} !px-3 !py-1.5 !text-xs`}
                      >
                        {probing ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
                        {probing ? 'Checking…' : 'Check again'}
                      </button>
                      {functionsUrl && (
                        <a
                          href={functionsUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1.5 px-2 py-1.5 text-xs text-mist-500 transition hover:text-mist-300"
                        >
                          <ExternalLink size={13} /> or deploy in the dashboard
                        </a>
                      )}
                    </div>
                    <p className="mt-2 flex items-start gap-1.5 text-xs text-mist-500">
                      <Terminal size={13} className="mt-0.5 shrink-0" />
                      Make sure the Supabase CLI is linked to this project before running the commands.
                    </p>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Step 6 — API key */}
          <div className="rounded-xl border border-line bg-ink-900/60 p-4">
            <div className="flex items-start gap-3">
              <StepIcon done={status.hasApiKey} />
              <div className="flex-1">
                <p className="text-sm font-semibold text-mist-100">6. Create an API key</p>
                {status.hasApiKey ? (
                  <p className="mt-1 text-sm text-mist-400">You have an active API key.</p>
                ) : (
                  <>
                    <p className="mt-1 text-sm text-mist-400">
                      Your backend uses this key to send AI events to the control plane. It is shown
                      once — store it somewhere safe.
                    </p>
                    <button
                      type="button"
                      onClick={goToApiKeys}
                      disabled={!status.hasOrg}
                      className={`${primaryBtn} mt-3`}
                    >
                      <KeyRound size={15} /> Go to API keys
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Step 7 — First request */}
          <div className="rounded-xl border border-line bg-ink-900/60 p-4">
            <div className="flex items-start gap-3">
              <StepIcon done={status.hasRequests} />
              <div className="flex-1">
                <p className="text-sm font-semibold text-mist-100">7. Receive your first request</p>
                {status.hasRequests ? (
                  <p className="mt-1 text-sm text-mist-400">
                    Requests are flowing — every one lands in the Requests section with its verdict.
                  </p>
                ) : (
                  <>
                    <p className="mt-1 text-sm text-mist-400">
                      Send an event through the API with your key, or run the simulator once to see
                      the full loop.
                    </p>
                    <button
                      type="button"
                      onClick={() => {
                        onClose();
                        onTrySimulator();
                      }}
                      disabled={!status.hasData}
                      className={`${primaryBtn} mt-3`}
                    >
                      <Activity size={15} /> Try the simulator
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {error ? <p className="text-sm text-rose-400">{error}</p> : null}

          {allDone && (
            <div className="rounded-xl border border-mint-400/30 bg-mint-400/10 p-4 text-center">
              <p className="text-sm font-semibold text-mint-300">
                You're all set — the full loop is live.
              </p>
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onTrySimulator();
                }}
                className={`${primaryBtn} mt-3 w-full !py-3`}
              >
                <Zap size={15} /> Try the simulator
              </button>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
