import { AnimatePresence, motion } from 'framer-motion';
import { Menu, ShieldCheck, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { navItems } from '../data/mock';
import { getSupabase, isSupabaseConfigured } from '../lib/supabase';
import { ThemeToggle } from './ThemeToggle';

interface NavbarProps {
  onSignIn: () => void;
  onProfile: () => void;
}

export function Navbar({ onSignIn, onProfile }: NavbarProps) {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);
  const [sessionEmail, setSessionEmail] = useState<string | null>(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    if (!isSupabaseConfigured()) return;
    const supabase = getSupabase();
    if (!supabase) return;
    supabase.auth.getSession().then(({ data }) => {
      setSessionEmail(data.session?.user.email ?? null);
    });
    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => {
      setSessionEmail(session?.user.email ?? null);
    });
    return () => {
      listener.subscription.unsubscribe();
    };
  }, []);

  const initial = (sessionEmail ?? '?').charAt(0).toUpperCase();

  const authButton = sessionEmail ? (
    <button
      type="button"
      onClick={onProfile}
      className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-mist-200 transition hover:text-mist-100"
      aria-label="Open your profile"
    >
      <span className="flex h-7 w-7 items-center justify-center rounded-full bg-accent-500/20 text-xs font-bold text-accent-600">
        {initial}
      </span>
      <span className="max-w-40 truncate">Account</span>
    </button>
  ) : (
    <button
      type="button"
      onClick={onSignIn}
      className="rounded-lg px-3 py-2 text-sm font-medium text-mist-300 transition hover:text-mist-100"
    >
      Sign In
    </button>
  );

  return (
    <header
      className={`fixed inset-x-0 top-0 z-[80] transition-all duration-300 ${
        scrolled ? 'border-b border-line bg-ink-900/85 backdrop-blur-md' : 'border-b border-transparent bg-transparent'
      }`}
    >
      <nav aria-label="Primary" className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <a href="#top" className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-line bg-ink-800">
            <ShieldCheck size={16} className="text-accent-600" />
          </span>
          <span className="text-[12px] font-bold uppercase tracking-[0.16em] text-mist-100">
            Data Control Plane
          </span>
        </a>

        <div className="hidden items-center gap-1 lg:flex">
          {navItems.map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="rounded-lg px-3 py-2 text-sm text-mist-400 transition hover:bg-ink-800 hover:text-mist-100"
            >
              {item.label}
            </a>
          ))}
        </div>

        <div className="hidden items-center gap-3 lg:flex">
          <ThemeToggle />
          {authButton}
          <a
            href="#get-started"
            className="btn-primary rounded-lg bg-accent-500 px-4 py-2 text-sm font-semibold text-accent-ink transition hover:bg-accent-400"
          >
            Get Started
          </a>
        </div>

        <button
          type="button"
          className="rounded-lg border border-line p-2 text-mist-200 lg:hidden"
          aria-expanded={open}
          aria-label={open ? 'Close menu' : 'Open menu'}
          onClick={() => setOpen((value) => !value)}
        >
          {open ? <X size={18} /> : <Menu size={18} />}
        </button>
      </nav>

      <AnimatePresence>
        {open ? (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.22 }}
            className="border-t border-line bg-ink-900/95 px-4 pb-6 pt-4 backdrop-blur-md lg:hidden"
          >
            <div className="flex flex-col gap-1">
              {navItems.map((item) => (
                <a
                  key={item.href}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  className="rounded-lg px-3 py-3 text-base text-mist-200 transition hover:bg-ink-800 hover:text-mist-100"
                >
                  {item.label}
                </a>
              ))}
            </div>
            <div className="mt-4 flex gap-3">
              {sessionEmail ? (
                <button
                  type="button"
                  onClick={() => {
                    setOpen(false);
                    onProfile();
                  }}
                  className="flex flex-1 items-center justify-center gap-2 rounded-lg border border-line px-4 py-3 text-sm font-medium text-mist-200"
                >
                  <span className="flex h-6 w-6 items-center justify-center rounded-full bg-accent-500/20 text-[11px] font-bold text-accent-600">
                    {initial}
                  </span>
                  Account
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => {
                    setOpen(false);
                    onSignIn();
                  }}
                  className="flex-1 rounded-lg border border-line px-4 py-3 text-sm font-medium text-mist-200"
                >
                  Sign In
                </button>
              )}
              <a
                href="#get-started"
                onClick={() => setOpen(false)}
                className="flex-1 rounded-lg bg-accent-500 px-4 py-3 text-center text-sm font-semibold text-accent-ink"
              >
                Get Started
              </a>
            </div>
            <div className="mt-4 flex items-center justify-between border-t border-line pt-4">
              <span className="text-xs font-semibold uppercase tracking-[0.18em] text-mist-500">Theme</span>
              <ThemeToggle />
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </header>
  );
}
