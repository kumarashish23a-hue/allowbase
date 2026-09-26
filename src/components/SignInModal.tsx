import { useEffect, useState } from 'react';
import { clearOrgCache, getSupabase, isSupabaseConfigured } from '../lib/supabase';
import { createOrganization, getActiveOrganization } from '../services/organizationService';
import { Modal } from './Modal';

interface SignInModalProps {
  open: boolean;
  onClose: () => void;
}

type Mode = 'signin' | 'signup';

export function SignInModal({ open, onClose }: SignInModalProps) {
  const configured = isSupabaseConfigured();
  const [mode, setMode] = useState<Mode>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [orgName, setOrgName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [sessionEmail, setSessionEmail] = useState<string | null>(null);
  const [sessionOrg, setSessionOrg] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !configured) return;
    const supabase = getSupabase();
    if (!supabase) return;
    let cancelled = false;
    supabase.auth.getSession().then(({ data }) => {
      if (cancelled) return;
      setSessionEmail(data.session?.user.email ?? null);
    });
    getActiveOrganization()
      .then((org) => {
        if (!cancelled) setSessionOrg(org?.name ?? null);
      })
      .catch(() => {
        if (!cancelled) setSessionOrg(null);
      });
    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => {
      setSessionEmail(session?.user.email ?? null);
      if (!session) {
        clearOrgCache();
        setSessionOrg(null);
      }
    });
    return () => {
      cancelled = true;
      listener.subscription.unsubscribe();
    };
  }, [open, configured]);

  if (!configured) {
    return (
      <Modal open={open} onClose={onClose} title="Sign in" subtitle="Authentication is not implemented in this prototype.">
        <p className="text-sm leading-relaxed text-mist-300">
          This demo focuses on the product experience: discovery, policy, monitoring, and audit. There are no user
          accounts, sessions, or identity providers connected.
        </p>
        <p className="mt-3 text-xs leading-relaxed text-mist-600">
          To enable sign-in, create a Supabase project, apply the migrations in supabase/migrations, deploy the
          evaluate-ai-request Edge Function, and set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.
        </p>
        <button
          type="button"
          onClick={onClose}
          className="mt-6 w-full rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-white transition hover:bg-accent-400"
        >
          Back to the prototype
        </button>
      </Modal>
    );
  }

  const signOut = async () => {
    const supabase = getSupabase();
    if (!supabase) return;
    await supabase.auth.signOut();
    clearOrgCache();
    setSessionEmail(null);
    setSessionOrg(null);
  };

  const submit = async () => {
    const supabase = getSupabase();
    if (!supabase) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      if (mode === 'signin') {
        const { error: signInError } = await supabase.auth.signInWithPassword({ email, password });
        if (signInError) throw signInError;
        const org = await getActiveOrganization();
        setSessionOrg(org?.name ?? null);
        onClose();
      } else {
        if (!orgName.trim()) throw new Error('Choose an organization name to continue.');
        const { data, error: signUpError } = await supabase.auth.signUp({
          email,
          password,
          options: { data: { full_name: fullName.trim() || undefined } },
        });
        if (signUpError) throw signUpError;
        if (!data.session) {
          setNotice('Account created. Check your email to confirm, then sign in.');
          setMode('signin');
          return;
        }
        await createOrganization(orgName.trim());
        const org = await getActiveOrganization();
        setSessionOrg(org?.name ?? null);
        onClose();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={sessionEmail ? 'Account' : mode === 'signin' ? 'Sign in' : 'Create account'}
      subtitle="Supabase Auth. Sessions never leave your browser."
    >
      {sessionEmail ? (
        <div className="space-y-4">
          <div className="rounded-xl border border-line bg-ink-950/60 p-4 text-sm">
            <p className="text-xs uppercase tracking-[0.16em] text-mist-600">Signed in as</p>
            <p className="mt-1 text-mist-100">{sessionEmail}</p>
            {sessionOrg ? <p className="mt-1 text-xs text-mist-500">Organization: {sessionOrg}</p> : null}
          </div>
          <button
            type="button"
            onClick={() => void signOut()}
            className="w-full rounded-xl border border-line px-4 py-3 text-sm font-semibold text-mist-200 transition hover:border-line-strong"
          >
            Sign out
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex rounded-xl border border-line bg-ink-950/60 p-1">
            {(['signin', 'signup'] as Mode[]).map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => {
                  setMode(item);
                  setError(null);
                  setNotice(null);
                }}
                className={`flex-1 rounded-lg px-3 py-2 text-sm font-semibold transition ${
                  mode === item ? 'bg-accent-500/20 text-accent-200' : 'text-mist-500 hover:text-mist-200'
                }`}
              >
                {item === 'signin' ? 'Sign in' : 'Create account'}
              </button>
            ))}
          </div>

          {mode === 'signup' ? (
            <>
              <div>
                <label htmlFor="auth-name" className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                  Full name
                </label>
                <input
                  id="auth-name"
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                  className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none"
                  placeholder="Ada Lovelace"
                  autoComplete="name"
                />
              </div>
              <div>
                <label htmlFor="auth-org" className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                  Organization
                </label>
                <input
                  id="auth-org"
                  value={orgName}
                  onChange={(event) => setOrgName(event.target.value)}
                  className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none"
                  placeholder="Acme Technologies"
                  autoComplete="organization"
                />
              </div>
            </>
          ) : null}

          <div>
            <label htmlFor="auth-email" className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
              Email
            </label>
            <input
              id="auth-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none"
              placeholder="you@company.com"
              autoComplete="email"
            />
          </div>
          <div>
            <label htmlFor="auth-password" className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
              Password
            </label>
            <input
              id="auth-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none"
              placeholder="••••••••"
              autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
            />
          </div>

          {error ? <p className="text-sm text-rose-400">{error}</p> : null}
          {notice ? <p className="text-sm text-mint-400">{notice}</p> : null}

          <button
            type="button"
            disabled={busy || !email || !password}
            onClick={() => void submit()}
            className="w-full rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-white transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy ? 'Please wait…' : mode === 'signin' ? 'Sign in' : 'Create account'}
          </button>
          <p className="text-xs leading-relaxed text-mist-600">
            New accounts get a profile automatically, plus an organization where you are the owner.
          </p>
        </div>
      )}
    </Modal>
  );
}
