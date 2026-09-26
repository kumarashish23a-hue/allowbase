import { AnimatePresence, motion } from 'framer-motion';
import { X } from 'lucide-react';
import { useEffect, useRef, type ReactNode } from 'react';

interface ModalProps {
  open: boolean;
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}

export function Modal({ open, title, subtitle, onClose, children, wide = false }: ModalProps) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    closeRef.current?.focus();
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
    };
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          className="fixed inset-0 z-[90] flex items-end justify-center p-4 sm:items-center"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          role="presentation"
          onClick={onClose}
        >
          <div className="absolute inset-0 bg-ink-950/80 backdrop-blur-sm" aria-hidden="true" />
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label={title}
            onClick={(event) => event.stopPropagation()}
            initial={{ opacity: 0, y: 24, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.98 }}
            transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
            className={`relative w-full ${wide ? 'max-w-3xl' : 'max-w-lg'} overflow-hidden rounded-2xl border border-line bg-ink-900 shadow-panel`}
          >
            <div className="flex items-start justify-between gap-6 border-b border-line px-6 py-5">
              <div>
                <h3 className="text-lg font-semibold tracking-tight text-mist-100">{title}</h3>
                {subtitle ? <p className="mt-1 text-sm text-mist-500">{subtitle}</p> : null}
              </div>
              <button
                ref={closeRef}
                type="button"
                onClick={onClose}
                aria-label="Close dialog"
                className="rounded-lg border border-line p-2 text-mist-400 transition hover:border-line-strong hover:text-mist-100"
              >
                <X size={16} />
              </button>
            </div>
            <div className="thin-scroll max-h-[72vh] overflow-y-auto px-6 py-6">{children}</div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}
