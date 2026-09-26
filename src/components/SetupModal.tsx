import { useEffect, useState } from 'react';
import {
  Building2,
  CheckCircle2,
  Circle,
  Copy,
  Database,
  ExternalLink,
  Loader2,
  RefreshCw,
  Zap,
} from 'lucide-react';
import { Modal } from './Modal';
import { createOrganization } from '../services/organizationService';
import {
  EDGE_FUNCTION_NAME,
  fetchEdgeFunctionCode,
  getFunctionsDashboardUrl,
  getSetupStatus,
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
  'inline-flex items-center justify-center gap-2 rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60';
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
  const [copying, setCopying] = useState(false);
  const [copied, setCopied] = useState(false);
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
    setCopied(false);
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

  const handleProbe = async () => {
    setProbing(true);
    try {
      const edgeFunction: EdgeFunctionStatus = await probeEdgeFunction();
      setStatus((prev) => (prev ? { ...prev, edgeFunction } : prev));
    } finally {
      setProbing(false);
    }
  };

  const handleCopyCode = async () => {
    setCopying(true);
    setError(null);
    try {
      const code = await fetchEdgeFunctionCode();
      await navigator.clipboard.writeText(code);
      setCopied(true);
    } catch {
      setError('Could not download the code. Open the GitHub link from the dashboard page instead.');
    } finally {
      setCopying(false);
    }
  };

  const allDone =
    !!status && status.signedIn && status.hasOrg && status.hasData && status.edgeFunction === 'deployed';
  const functionsUrl = getFunctionsDashboardUrl();

  return (
    <Modal open={open} onClose={onClose} title="Workspace setup" subtitle="Three quick steps to go from demo to live.">
      {loading || !status ? (
        <div className="flex items-center justify-center gap-2 py-10 text-sm text-mist-400">
          <Loader2 size={16} className="animate-spin" /> Checking your setup…
        </div>
      ) : (
        <div className="space-y-4">
          {/* Step 1 — Sign in */}
          <div className="rounded-2xl border border-line bg-ink-900/60 p-4">
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
          <div className="rounded-2xl border border-line bg-ink-900/60 p-4">
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

          {/* Step 3 — Starter data */}
          <div className="rounded-2xl border border-line bg-ink-900/60 p-4">
            <div className="flex items-start gap-3">
              <StepIcon done={status.hasData} pending={loadingData} />
              <div className="flex-1">
                <p className="text-sm font-semibold text-mist-100">3. Load a starter workspace</p>
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

          {/* Step 4 — Edge Function */}
          <div className="rounded-2xl border border-line bg-ink-900/60 p-4">
            <div className="flex items-start gap-3">
              <StepIcon done={status.edgeFunction === 'deployed'} pending={probing} />
              <div className="flex-1">
                <p className="text-sm font-semibold text-mist-100">4. Deploy the evaluation service</p>
                {status.edgeFunction === 'deployed' ? (
                  <p className="mt-1 text-sm text-mist-400">
                    The <span className="font-mono text-mist-200">{EDGE_FUNCTION_NAME}</span> service is live —
                    simulations run real policy evaluations.
                  </p>
                ) : (
                  <>
                    <p className="mt-1 text-sm text-mist-400">
                      This one lives in your Supabase project, so it needs two minutes in the Supabase dashboard:
                    </p>
                    <ol className="mt-2 list-decimal space-y-2 pl-5 text-sm text-mist-300">
                      <li>
                        Open Supabase Functions and create a function named{' '}
                        <span className="font-mono text-mist-100">{EDGE_FUNCTION_NAME}</span>.
                        {functionsUrl && (
                          <a
                            href={functionsUrl}
                            target="_blank"
                            rel="noreferrer"
                            className={`${secondaryBtn} ml-2 !px-3 !py-1.5 !text-xs`}
                          >
                            <ExternalLink size={13} /> Open Supabase Functions
                          </a>
                        )}
                      </li>
                      <li>
                        Replace the sample code with the function code, then click Deploy.
                        <button
                          type="button"
                          onClick={() => void handleCopyCode()}
                          disabled={copying}
                          className={`${secondaryBtn} ml-2 !px-3 !py-1.5 !text-xs`}
                        >
                          {copying ? <Loader2 size={13} className="animate-spin" /> : <Copy size={13} />}
                          {copied ? 'Copied!' : copying ? 'Copying…' : 'Copy function code'}
                        </button>
                      </li>
                      <li>
                        Come back here and check.
                        <button
                          type="button"
                          onClick={() => void handleProbe()}
                          disabled={probing}
                          className={`${secondaryBtn} ml-2 !px-3 !py-1.5 !text-xs`}
                        >
                          {probing ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
                          {probing ? 'Checking…' : 'Check again'}
                        </button>
                      </li>
                    </ol>
                    {status.edgeFunction === 'missing' && (
                      <p className="mt-2 text-xs text-amber-300/90">
                        Not deployed yet — the simulator is still using the offline mock.
                      </p>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>

          {error ? <p className="text-sm text-rose-400">{error}</p> : null}

          {allDone && (
            <button
              type="button"
              onClick={() => {
                onClose();
                onTrySimulator();
              }}
              className={`${primaryBtn} w-full !py-3`}
            >
              <Zap size={15} /> Try the simulator — it is live now
            </button>
          )}
        </div>
      )}
    </Modal>
  );
}
