import { useEffect, useState } from 'react';
import { consumeForceLogoutNotice } from '../lib/forceLogout';
import { getSupabase, isSupabaseConfigured } from '../lib/supabase';
import {
  completeOnboarding,
  getPendingOnboarding,
  savePendingOnboarding,
  type PendingOnboarding,
} from '../services/organizationService';
import { Modal } from './Modal';

interface SignInModalProps {
  open: boolean;
  onClose: () => void;
  /** Called after a successful sign-in / sign-up so the app can react. */
  onAuthSuccess: () => void;
}

type Mode = 'signin' | 'signup';
type SignupStep = 0 | 1 | 2;

const inputClass =
  'mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none';
const labelClass = 'text-xs font-semibold uppercase tracking-[0.16em] text-mist-500';

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function friendlyAuthError(message: string): string {
  if (/invalid login credentials/i.test(message)) return 'The email or password is incorrect.';
  if (/email not confirmed/i.test(message)) return 'Confirm your email before signing in, then try again.';
  if (/already registered|already exists/i.test(message)) return 'An account with this email already exists. Sign in instead.';
  if (/password/i.test(message) && /characters|length|weak/i.test(message)) {
    return 'Use a password with at least 8 characters.';
  }
  return message;
}

export function SignInModal({ open, onClose, onAuthSuccess }: SignInModalProps) {
  const configured = isSupabaseConfigured();
  const [mode, setMode] = useState<Mode>('signin');
  const [signupStep, setSignupStep] = useState<SignupStep>(0);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [jobTitle, setJobTitle] = useState('');
  const [department, setDepartment] = useState('');
  const [orgName, setOrgName] = useState('');
  const [industry, setIndustry] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (open && consumeForceLogoutNotice()) {
      setNotice('Your workspace admin signed you out. Sign in again to continue.');
    }
  }, [open]);

  const switchMode = (nextMode: Mode) => {
    setMode(nextMode);
    setSignupStep(0);
    setError(null);
    setNotice(null);
  };

  const validateSignupStep = (): string | null => {
    if (signupStep === 0) {
      if (fullName.trim().length < 2) return 'Enter your full name.';
      if (fullName.trim().length > 120) return 'Your name must be 120 characters or fewer.';
      return null;
    }
    if (signupStep === 1) {
      if (orgName.trim().length < 2) return 'Enter your organization name.';
      if (orgName.trim().length > 120) return 'Organization name must be 120 characters or fewer.';
      return null;
    }
    if (!normalizeEmail(email) || !/^\S+@\S+\.\S+$/.test(normalizeEmail(email))) {
      return 'Enter a valid email address.';
    }
    if (password.length < 8) return 'Use a password with at least 8 characters.';
    if (password !== confirmPassword) return 'The passwords do not match.';
    return null;
  };

  const finishAuthenticatedOnboarding = async (draft: PendingOnboarding | null) => {
    if (draft) await completeOnboarding(draft);
  };

  const submit = async () => {
    const supabase = getSupabase();
    if (!supabase) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const normalizedEmail = normalizeEmail(email);
      if (mode === 'signin') {
        if (!/^\S+@\S+\.\S+$/.test(normalizedEmail)) throw new Error('Enter a valid email address.');
        if (!password) throw new Error('Enter your password.');
        const { error: signInError } = await supabase.auth.signInWithPassword({
          email: normalizedEmail,
          password,
        });
        if (signInError) throw signInError;
        await finishAuthenticatedOnboarding(getPendingOnboarding(normalizedEmail));
        onAuthSuccess();
        return;
      }

      const stepError = validateSignupStep();
      if (stepError) {
        setError(stepError);
        return;
      }
      if (signupStep < 2) {
        setSignupStep((current) => (current + 1) as SignupStep);
        return;
      }

      const draft: PendingOnboarding = {
        email: normalizedEmail,
        fullName: fullName.trim(),
        jobTitle: jobTitle.trim(),
        department: department.trim(),
        organizationName: orgName.trim(),
        industry: industry.trim(),
      };
      const { data, error: signUpError } = await supabase.auth.signUp({
        email: normalizedEmail,
        password,
        options: { data: { full_name: draft.fullName } },
      });
      if (signUpError) throw signUpError;

      if (!data.session) {
        // Email confirmation can happen in another tab, so keep only the
        // non-secret fields needed to finish onboarding after sign-in.
        savePendingOnboarding(draft);
        setPassword('');
        setConfirmPassword('');
        setMode('signin');
        setSignupStep(0);
        setNotice('Account created. Confirm your email, then sign in to finish setting up your workspace.');
        return;
      }

      await completeOnboarding(draft);
      onAuthSuccess();
    } catch (err) {
      setError(friendlyAuthError(err instanceof Error ? err.message : 'Something went wrong.'));
    } finally {
      setBusy(false);
    }
  };

  if (!configured) {
    return (
      <Modal open={open} onClose={onClose} title="Sign in" subtitle="Authentication is not configured yet.">
        <p className="text-sm leading-relaxed text-mist-300">
          Connect a Supabase project to enable accounts, workspaces, and live policy evaluation. The public demo still
          works without an account.
        </p>
        <p className="mt-3 text-xs leading-relaxed text-mist-600">
          Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY after applying the migrations and deploying the required
          Edge Functions.
        </p>
        <button
          type="button"
          onClick={onClose}
          className="mt-6 w-full rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-accent-ink transition hover:bg-accent-400"
        >
          Back to the prototype
        </button>
      </Modal>
    );
  }

  const signupTitles = ['Your profile', 'Your workspace', 'Account security'];
  const signupDescriptions = [
    'Tell us who will manage this workspace.',
    'Give your workspace a clear identity. You can change these details later.',
    'Use an email you can confirm and a strong password.',
  ];

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={mode === 'signin' ? 'Welcome back' : signupTitles[signupStep]}
      subtitle={mode === 'signin' ? 'Sign in to your AllowBase workspace.' : signupDescriptions[signupStep]}
    >
      <div className="space-y-4">
        <div className="flex rounded-xl border border-line bg-ink-950/60 p-1">
          {(['signin', 'signup'] as Mode[]).map((item) => (
            <button
              key={item}
              type="button"
              onClick={() => switchMode(item)}
              className={`flex-1 rounded-lg px-3 py-2 text-sm font-semibold transition ${
                mode === item ? 'bg-accent-500/20 text-accent-600' : 'text-mist-500 hover:text-mist-200'
              }`}
            >
              {item === 'signin' ? 'Sign in' : 'Create account'}
            </button>
          ))}
        </div>

        {mode === 'signup' ? (
          <>
            <div className="flex items-center gap-2" aria-label={`Signup step ${signupStep + 1} of 3`}>
              {[0, 1, 2].map((step) => (
                <div key={step} className="flex flex-1 items-center gap-2">
                  <span
                    className={`h-1.5 flex-1 rounded-full ${step <= signupStep ? 'bg-accent-500' : 'bg-line'}`}
                  />
                  <span className="sr-only">Step {step + 1}</span>
                </div>
              ))}
            </div>

            {signupStep === 0 ? (
              <>
                <div>
                  <label htmlFor="auth-name" className={labelClass}>
                    Full name
                  </label>
                  <input
                    id="auth-name"
                    value={fullName}
                    onChange={(event) => setFullName(event.target.value)}
                    className={inputClass}
                    placeholder="Ada Lovelace"
                    autoComplete="name"
                    autoFocus
                  />
                </div>
                <div>
                  <label htmlFor="auth-title" className={labelClass}>
                    Job title <span className="font-normal normal-case tracking-normal text-mist-600">(optional)</span>
                  </label>
                  <input
                    id="auth-title"
                    value={jobTitle}
                    onChange={(event) => setJobTitle(event.target.value)}
                    className={inputClass}
                    placeholder="Security engineer"
                    autoComplete="organization-title"
                  />
                </div>
                <div>
                  <label htmlFor="auth-department" className={labelClass}>
                    Department <span className="font-normal normal-case tracking-normal text-mist-600">(optional)</span>
                  </label>
                  <input
                    id="auth-department"
                    value={department}
                    onChange={(event) => setDepartment(event.target.value)}
                    className={inputClass}
                    placeholder="Platform security"
                    autoComplete="organization"
                  />
                </div>
              </>
            ) : null}

            {signupStep === 1 ? (
              <>
                <div>
                  <label htmlFor="auth-org" className={labelClass}>
                    Organization name
                  </label>
                  <input
                    id="auth-org"
                    value={orgName}
                    onChange={(event) => setOrgName(event.target.value)}
                    className={inputClass}
                    placeholder="Acme Technologies"
                    autoComplete="organization"
                    autoFocus
                  />
                </div>
                <div>
                  <label htmlFor="auth-industry" className={labelClass}>
                    Industry <span className="font-normal normal-case tracking-normal text-mist-600">(optional)</span>
                  </label>
                  <input
                    id="auth-industry"
                    value={industry}
                    onChange={(event) => setIndustry(event.target.value)}
                    className={inputClass}
                    placeholder="Financial services"
                    autoComplete="organization"
                  />
                </div>
                <p className="text-xs leading-relaxed text-mist-600">
                  We create one private workspace and make you its owner. You can invite teammates after setup.
                </p>
              </>
            ) : null}

            {signupStep === 2 ? (
              <>
                <div>
                  <label htmlFor="auth-email" className={labelClass}>
                    Email
                  </label>
                  <input
                    id="auth-email"
                    type="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    className={inputClass}
                    placeholder="you@company.com"
                    autoComplete="email"
                    autoFocus
                  />
                </div>
                <div>
                  <label htmlFor="auth-password" className={labelClass}>
                    Password
                  </label>
                  <input
                    id="auth-password"
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    className={inputClass}
                    placeholder="At least 8 characters"
                    autoComplete="new-password"
                  />
                </div>
                <div>
                  <label htmlFor="auth-confirm-password" className={labelClass}>
                    Confirm password
                  </label>
                  <input
                    id="auth-confirm-password"
                    type="password"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    className={inputClass}
                    placeholder="Repeat your password"
                    autoComplete="new-password"
                  />
                </div>
                <p className="text-xs leading-relaxed text-mist-600">
                  Your password is handled by Supabase Auth and is never stored in AllowBase profile data.
                </p>
              </>
            ) : null}
          </>
        ) : (
          <>
            <div>
              <label htmlFor="auth-signin-email" className={labelClass}>
                Email
              </label>
              <input
                id="auth-signin-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                className={inputClass}
                placeholder="you@company.com"
                autoComplete="email"
                autoFocus
              />
            </div>
            <div>
              <label htmlFor="auth-signin-password" className={labelClass}>
                Password
              </label>
              <input
                id="auth-signin-password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className={inputClass}
                placeholder="Your password"
                autoComplete="current-password"
              />
            </div>
            {getPendingOnboarding(normalizeEmail(email)) ? (
              <p className="rounded-xl border border-accent-400/20 bg-accent-500/5 px-3 py-2.5 text-xs leading-relaxed text-accent-300">
                Your confirmed signup is ready. Signing in will finish creating your workspace.
              </p>
            ) : null}
          </>
        )}

        {error ? <p className="text-sm text-rose-400">{error}</p> : null}
        {notice ? <p className="text-sm text-mint-400">{notice}</p> : null}

        <div className="flex gap-3">
          {mode === 'signup' && signupStep > 0 ? (
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setError(null);
                setSignupStep((current) => (current - 1) as SignupStep);
              }}
              className="flex-1 rounded-xl border border-line px-4 py-3 text-sm font-semibold text-mist-200 transition hover:border-line-strong hover:text-mist-100 disabled:opacity-60"
            >
              Back
            </button>
          ) : null}
          <button
            type="button"
            disabled={busy}
            onClick={() => void submit()}
            className="flex-1 rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-accent-ink transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy
              ? 'Please wait…'
              : mode === 'signin'
                ? 'Sign in'
                : signupStep < 2
                  ? 'Continue'
                  : 'Create workspace'}
          </button>
        </div>

        {mode === 'signup' ? (
          <p className="text-xs leading-relaxed text-mist-600">
            If email confirmation is enabled, your workspace details are kept locally without your password and applied
            when you return to sign in.
          </p>
        ) : null}
      </div>
    </Modal>
  );
}
