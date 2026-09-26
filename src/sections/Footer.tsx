import { ShieldCheck } from 'lucide-react';

const columns: { title: string; links: { label: string; href: string }[] }[] = [
  {
    title: 'Product',
    links: [
      { label: 'Platform', href: '#platform' },
      { label: 'Policy Engine', href: '#platform' },
      { label: 'AI Agents', href: '#platform' },
      { label: 'Pricing', href: '#pricing' },
    ],
  },
  {
    title: 'Solutions',
    links: [
      { label: 'Enterprise AI', href: '#solutions' },
      { label: 'AI Agents', href: '#solutions' },
      { label: 'Data Security', href: '#solutions' },
      { label: 'Regulated Organizations', href: '#solutions' },
    ],
  },
  {
    title: 'Developers',
    links: [
      { label: 'API Concept', href: '#developers' },
      { label: 'Architecture', href: '#developers' },
      { label: 'Security', href: '#security' },
    ],
  },
  {
    title: 'Company',
    links: [
      { label: 'About', href: '#top' },
      { label: 'Careers', href: '#top' },
      { label: 'Contact', href: '#get-started' },
    ],
  },
];

export function Footer() {
  return (
    <footer className="border-t border-line bg-ink-950/80">
      <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8">
        <div className="grid gap-10 lg:grid-cols-[1.2fr_2fr]">
          <div>
            <div className="flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-line bg-ink-800">
                <ShieldCheck size={18} className="text-accent-600" />
              </span>
              <span className="text-[13px] font-bold uppercase tracking-[0.18em] text-mist-100">
                Data Control Plane
              </span>
            </div>
            <p className="mt-4 max-w-xs text-sm leading-relaxed text-mist-500">
              Control the data layer behind AI.
            </p>
            <p className="mt-4 max-w-xs text-xs leading-relaxed text-mist-600">
              Security model:{' '}
              <a href="#security" className="text-mist-500 underline decoration-line-strong underline-offset-2 transition hover:text-mist-200">
                metadata-only discovery, deterministic policy, deny-by-default enforcement
              </a>
              .
            </p>
            <p className="mt-3 text-xs text-mist-600">Frontend prototype. All data shown is simulated.</p>
          </div>
          <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
            {columns.map((column) => (
              <div key={column.title}>
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-mist-500">{column.title}</p>
                <ul className="mt-4 space-y-2.5">
                  {column.links.map((link) => (
                    <li key={`${column.title}-${link.label}`}>
                      <a href={link.href} className="text-sm text-mist-400 transition hover:text-mist-100">
                        {link.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-12 flex flex-col items-start justify-between gap-4 border-t border-line pt-6 sm:flex-row sm:items-center">
          <p className="text-xs text-mist-600">© 2026 Data Control Plane. Prototype concept.</p>
          <div className="flex gap-6">
            {[
              { label: 'Privacy', href: '#top' },
              { label: 'Terms', href: '#top' },
              { label: 'Security', href: '#security' },
            ].map((link) => (
              <a key={link.label} href={link.href} className="text-xs text-mist-500 transition hover:text-mist-200">
                {link.label}
              </a>
            ))}
          </div>
        </div>
      </div>
    </footer>
  );
}
