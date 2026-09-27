import { Check, Copy } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useState } from 'react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { developerRequest, developerResponse } from '../data/mock';

const architecture = ['Application', 'AllowBase API', 'Policy Engine', 'Data Classification', 'AI Provider'];

function CodeBlock({ title, code, id }: { title: string; code: string; id: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = code;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };

  return (
    <div className="overflow-hidden rounded-xl border border-line bg-ink-950/80">
      <div className="flex items-center justify-between border-b border-line px-4 py-3">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-mist-500">{title}</p>
        <button
          type="button"
          onClick={copy}
          aria-label={`Copy ${id}`}
          className="inline-flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1.5 text-xs text-mist-300 transition hover:border-line-strong hover:text-mist-100"
        >
          {copied ? <Check size={13} className="text-mint-400" /> : <Copy size={13} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="code-block thin-scroll overflow-x-auto p-5 text-mist-200">{code}</pre>
    </div>
  );
}

export function Developers() {
  return (
    <section id="developers" className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
      <SectionHeading
        eyebrow="Developers"
        title="Built to fit your existing AI stack."
        description="Drop a policy check in front of any model call. The endpoint below is live — create an API key in the section under this one and call it from your backend."
      />

      <div className="mt-12 grid gap-6 lg:grid-cols-[1fr_1.2fr]">
        <Reveal>
          <div className="rounded-xl border border-line bg-ink-900/60 p-6 shadow-card sm:p-8">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-mist-500">Conceptual architecture</p>
            <div className="mt-6 space-y-0">
              {architecture.map((layer, index) => (
                <div key={layer}>
                  <div
                    className={`rounded-xl border px-4 py-3 text-sm ${
                      index === 1
                        ? 'border-accent-400/50 bg-accent-500/10 font-semibold text-mist-100'
                        : 'border-line bg-ink-950/60 text-mist-300'
                    }`}
                  >
                    {layer}
                  </div>
                  {index < architecture.length - 1 ? (
                    <div className="flex justify-center py-1.5" aria-hidden="true">
                      <span className="text-mist-600">↓</span>
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="space-y-4">
            <CodeBlock title="Request" code={developerRequest} id="request example" />
            <CodeBlock title="Response" code={developerResponse} id="response example" />
            <p className="text-xs text-mist-600">
              Live endpoint. Check-mode: only call the model when <span className="font-mono">decision</span> is{' '}
              <span className="font-mono">allow</span>; treat <span className="font-mono">require_approval</span> as a
              pause for a human. <Link to="/app#api-keys" className="underline hover:text-mist-400">Get an API key</Link>.
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
