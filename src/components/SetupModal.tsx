import { useEffect, useState } from 'react';
import {
  Activity,
  ArrowLeft,
  ArrowRight,
  Building2,
  Check,
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
  'mt-3 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none';
const primaryBtn =
  'inline-flex items-center justify-center gap-2 rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-accent-ink transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60';
const secondaryBtn =
  'inline-flex items-center justify-center gap-2 rounded-xl border border-line px-4 py-2.5 text-sm font-semibold text-mist-200 transition hover:border-line-strong hover:text-mist-100 disabled:cursor-not-allowed disabled:opacity-60';

const STEP_TITLES = [
  'Sign in',
  'Create your organization',
  'Run the database migrations',
  'Load a starter workspace',
  'Deploy the edge functions',
  'Create an API key',
  'Receive your first request',
];

function stepDoneFlags(status: SetupStatus): boolean[] {
  return [
    status.signedIn,
    status.hasOrg,
    status.migrations.state === 'ok',
    status.hasData,
    status.functions[EDGE_FUNCTION_NAME] === 'deployed' &&
      status.functions[INGEST_FUNCTION_NAME] === 'deployed',
    status.hasApiKey,
    status.hasRequests,
  ];
}

function firstIncompleteOf(status: SetupStatus): number {
  const idx = stepDoneFlags(status).findIndex((done) => !done);
  return idx === -1 ? STEP_TITLES.length : idx;
}

export function SetupModal({ open, onClose, onSignIn, onTrySimulator }: SetupModalProps) {
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [stepIndex, setStepIndex] = useState(0);
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
      const next = await getSetupStatus();
      setStatus(next);
      // Always land on the first unfinished step.
      setStepIndex(firstIncompleteOf(next));
    } catch {
      setError('Could not check your setup status. Try again.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!open) return;
    setCopiedCmd(null);
    setError(null);
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

  const goToApiKeys = () => {
    onClose();
    // Let the modal finish closing before scrolling.
    window.setTimeout(() => {
      document.getElementById('api-keys')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 150);
  };

  const doneFlags = status ? stepDoneFlags(status) : [];
  const doneCount = doneFlags.filter(Boolean).length;
  const totalSteps = STEP_TITLES.length;
  const firstIncomplete = status ? firstIncompleteOf(status) : 0;
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

  const renderStepBody = () => {
    if (!status) return null;
    switch (stepIndex) {
      case 0:
        return (
          <>
            <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
              {status.signedIn
                ? 'You are signed in. On to the next step.'
                : 'You need an account before anything else works.'}
            </p>
            {!status.signedIn && (
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
            )}
          </>
        );
      case 1:
        return (
          <>
            {status.hasOrg ? (
              <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                Using{' '}
                <span className="font-semibold text-mist-200">{status.orgName ?? 'your organization'}</span>.
              </p>
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
      case 2:
        return (
          <>
            {status.migrations.state === 'ok' ? (
              <p className="mt-2 text-[15px] leading-relaxed text-mist-400">All tables are in place.</p>
            ) : status.migrations.state === 'missing' ? (
              <>
                <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                  {status.migrations.missingFiles.length === 1 ? 'This file has' : 'These files have'} not
                  been run yet:
                </p>
                <ul className="mt-3 space-y-2">
                  {status.migrations.missingFiles.map((file) => (
                    <li
                      key={file}
                      className="flex items-center gap-2 rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 font-mono text-sm text-mist-200"
                    >
                      <Table size={15} className="shrink-0 text-accent-400" />
                      supabase/migrations/{file}
                    </li>
                  ))}
                </ul>
                <p className="mt-3 text-[15px] leading-relaxed text-mist-400">
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
                {sqlEditorUrl && (
                  <a
                    href={sqlEditorUrl}
                    target="_blank"
                    rel="noreferrer"
                    className={`${primaryBtn} mt-4 w-full !py-3 !text-base`}
                  >
                    <ExternalLink size={16} /> Open SQL editor
                  </a>
                )}
                <button
                  type="button"
                  onClick={() => void refresh()}
                  className={`${secondaryBtn} mt-2 w-full`}
                >
                  <RefreshCw size={15} /> I've run them — check again
                </button>
              </>
            ) : (
              <>
                <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                  Could not check the database. Make sure you are signed in, then try again.
                </p>
                <button
                  type="button"
                  onClick={() => void refresh()}
                  className={`${secondaryBtn} mt-4 w-full`}
                >
                  <RefreshCw size={15} /> Check again
                </button>
              </>
            )}
          </>
        );
      case 3:
        return (
          <>
            {status.hasData ? (
              <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                Your workspace already has data.
              </p>
            ) : (
              <>
                <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                  Adds 2 data sources, 2 data assets, 2 AI models, 1 agent, 2 policies and 1 finding —
                  everything the simulator needs. Nothing is overwritten.
                </p>
                <button
                  type="button"
                  disabled={!status.hasOrg || loadingData}
                  onClick={() => void handleLoadData()}
                  className={`${primaryBtn} mt-4 w-full !py-3 !text-base`}
                >
                  {loadingData ? <Loader2 size={16} className="animate-spin" /> : <Database size={16} />}
                  {loadingData ? 'Loading…' : 'Load starter workspace'}
                </button>
              </>
            )}
          </>
        );
      case 4: {
        const bothLive =
          status.functions[EDGE_FUNCTION_NAME] === 'deployed' &&
          status.functions[INGEST_FUNCTION_NAME] === 'deployed';
        return (
          <>
            {bothLive ? (
              <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                Both services are live — simulations run real policy evaluations and the API accepts
                events.
              </p>
            ) : (
              <>
                <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                  These run inside your Supabase project. From your{' '}
                  <span className="font-mono text-mist-200">dataplane</span> project folder, run:
                </p>
                <ul className="mt-3 space-y-2">
                  {([EDGE_FUNCTION_NAME, INGEST_FUNCTION_NAME] as const).map((fn) => {
                    const deployed = status.functions[fn] === 'deployed';
                    const command = `npx supabase functions deploy ${fn}`;
                    return (
                      <li
                        key={fn}
                        className="rounded-xl border border-line bg-ink-950/70 px-3 py-2.5"
                      >
                        <div className="flex items-center gap-2">
                          {deployed ? (
                            <CheckCircle2 size={15} className="shrink-0 text-mint-400" />
                          ) : (
                            <Circle size={15} className="shrink-0 text-mist-600" />
                          )}
                          <span className="font-mono text-sm text-mist-200">{fn}</span>
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
                  className={`${primaryBtn} mt-4 w-full !py-3 !text-base`}
                >
                  {probing ? <Loader2 size={16} className="animate-spin" /> : <RefreshCw size={16} />}
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
            )}
          </>
        );
      }
      case 5:
        return (
          <>
            {status.hasApiKey ? (
              <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                You have an active API key.
              </p>
            ) : (
              <>
                <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                  Your backend uses this key to send AI events to the control plane. It is shown once —
                  store it somewhere safe.
                </p>
                <button
                  type="button"
                  onClick={goToApiKeys}
                  disabled={!status.hasOrg}
                  className={`${primaryBtn} mt-4 w-full !py-3 !text-base`}
                >
                  <KeyRound size={16} /> Go to API keys
                </button>
              </>
            )}
          </>
        );
      case 6:
        return (
          <>
            {status.hasRequests ? (
              <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                Requests are flowing — every one lands in the Requests section with its verdict.
              </p>
            ) : (
              <>
                <p className="mt-2 text-[15px] leading-relaxed text-mist-400">
                  Send an event through the API with your key, or run the simulator once to see the
                  full loop.
                </p>
                <button
                  type="button"
                  onClick={() => {
                    onClose();
                    onTrySimulator();
                  }}
                  disabled={!status.hasData}
                  className={`${primaryBtn} mt-4 w-full !py-3 !text-base`}
                >
                  <Activity size={16} /> Try the simulator
                </button>
              </>
            )}
          </>
        );
      default:
        return null;
    }
  };

  const stepDone = status ? doneFlags[stepIndex] : false;
  const subtitle = allDone
    ? 'All done — nice work.'
    : status
      ? `Step ${Math.min(stepIndex + 1, totalSteps)} of ${totalSteps}`
      : 'From sign-in to your first live AI request.';

  return (
    <Modal open={open} onClose={onClose} title="Workspace setup" subtitle={subtitle}>
      {loading || !status ? (
        <div className="flex items-center justify-center gap-2 py-10 text-sm text-mist-400">
          <Loader2 size={16} className="animate-spin" /> Checking your setup…
        </div>
      ) : (
        <div>
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
                You're all set — the full loop is live.
              </p>
              <p className="mt-1 text-sm text-mist-400">
                Every AI call is now on the record, with its verdict and risk level.
              </p>
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onTrySimulator();
                }}
                className={`${primaryBtn} mt-5 w-full !py-3 !text-base`}
              >
                <Zap size={16} /> Try the simulator
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
