import { AnimatePresence, motion } from 'framer-motion';
import { ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { faqs } from '../data/mock';

export function Faq() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  return (
    <section className="mx-auto max-w-4xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
      <SectionHeading
        eyebrow="FAQ"
        title="Prototype, honestly labeled."
        description="What this demo is — and what it deliberately is not."
      />
      <div className="mt-10 space-y-3">
        {faqs.map((faq, index) => {
          const open = openIndex === index;
          return (
            <Reveal key={faq.question} delay={index * 0.04}>
              <div className={`overflow-hidden rounded-2xl border transition ${open ? 'border-line-strong bg-ink-900/70' : 'border-line bg-ink-900/40'}`}>
                <button
                  type="button"
                  onClick={() => setOpenIndex(open ? null : index)}
                  aria-expanded={open}
                  className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left sm:px-6"
                >
                  <span className="text-sm font-semibold text-mist-100 sm:text-base">{faq.question}</span>
                  <ChevronDown
                    size={18}
                    className={`shrink-0 text-mist-400 transition-transform duration-300 ${open ? 'rotate-180' : ''}`}
                  />
                </button>
                <AnimatePresence initial={false}>
                  {open ? (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
                    >
                      <p className="px-5 pb-5 text-sm leading-relaxed text-mist-400 sm:px-6">{faq.answer}</p>
                    </motion.div>
                  ) : null}
                </AnimatePresence>
              </div>
            </Reveal>
          );
        })}
      </div>
    </section>
  );
}
