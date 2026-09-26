import {
  Eye,
  FileSearch,
  Fingerprint,
  GitBranch,
  KeyRound,
  Lock,
  Radar,
  ScrollText,
  SlidersHorizontal,
} from 'lucide-react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { securityFeatures } from '../data/mock';

const icons = [Eye, FileSearch, Lock, SlidersHorizontal, KeyRound, Fingerprint, ScrollText, Radar, GitBranch];

export function Security() {
  return (
    <section id="security" className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="Security"
          title="Security designed for the AI era."
          description="One consistent model for discovery, detection, enforcement, and audit across every AI system."
        />
        <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {securityFeatures.map((feature, index) => {
            const Icon = icons[index % icons.length];
            return (
              <Reveal key={feature.title} delay={index * 0.05}>
                <div className="h-full rounded-xl border border-line bg-ink-950/60 p-6 shadow-card transition hover:border-line-strong">
                  <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-line bg-ink-800 text-accent-600">
                    <Icon size={18} />
                  </span>
                  <h3 className="mt-4 text-base font-semibold text-mist-100">{feature.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-mist-400">{feature.description}</p>
                </div>
              </Reveal>
            );
          })}
        </div>
      </div>
    </section>
  );
}
