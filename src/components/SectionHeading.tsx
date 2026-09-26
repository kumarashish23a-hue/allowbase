import type { ReactNode } from 'react';
import { Reveal } from './Reveal';

interface SectionHeadingProps {
  eyebrow: string;
  title: ReactNode;
  description?: string;
  align?: 'left' | 'center';
}

export function SectionHeading({ eyebrow, title, description, align = 'center' }: SectionHeadingProps) {
  const alignClass = align === 'center' ? 'text-center mx-auto' : 'text-left';
  return (
    <Reveal className={`max-w-3xl ${alignClass}`}>
      <p className="text-xs font-semibold uppercase tracking-[0.22em] text-accent-600">{eyebrow}</p>
      <h2 className="mt-4 text-balance text-3xl font-semibold tracking-tight text-mist-100 sm:text-4xl lg:text-[2.75rem] lg:leading-[1.1]">
        {title}
      </h2>
      {description ? <p className="mt-5 text-base leading-relaxed text-mist-400 sm:text-lg">{description}</p> : null}
    </Reveal>
  );
}
