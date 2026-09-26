import { AnimatePresence, motion } from 'framer-motion';
import { Menu, ShieldCheck, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { navItems } from '../data/mock';

interface NavbarProps {
  onSignIn: () => void;
}

export function Navbar({ onSignIn }: NavbarProps) {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-[80] transition-all duration-300 ${
        scrolled ? 'border-b border-line bg-ink-950/85 backdrop-blur-xl' : 'border-b border-transparent bg-transparent'
      }`}
    >
      <nav aria-label="Primary" className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <a href="#top" className="flex items-center gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-line bg-ink-800">
            <ShieldCheck size={18} className="text-accent-300" />
          </span>
          <span className="text-[13px] font-bold uppercase tracking-[0.18em] text-mist-100">
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
          <button
            type="button"
            onClick={onSignIn}
            className="rounded-lg px-3 py-2 text-sm font-medium text-mist-300 transition hover:text-mist-100"
          >
            Sign In
          </button>
          <a
            href="#get-started"
            className="rounded-lg bg-accent-500 px-4 py-2 text-sm font-semibold text-white shadow-card transition hover:bg-accent-400"
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
            className="border-t border-line bg-ink-950/95 px-4 pb-6 pt-4 backdrop-blur-xl lg:hidden"
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
              <a
                href="#get-started"
                onClick={() => setOpen(false)}
                className="flex-1 rounded-lg bg-accent-500 px-4 py-3 text-center text-sm font-semibold text-white"
              >
                Get Started
              </a>
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </header>
  );
}
