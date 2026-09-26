import { useEffect, useRef } from 'react';

interface VantaNetInstance {
  destroy: () => void;
}

/**
 * Interactive Vanta.js NET backdrop: a living network of nodes and links
 * that reacts to the cursor. Customized per theme — the net color and canvas
 * background follow the active theme, airy spacing, faded out toward the
 * bottom so content below the hero fold stays clean.
 *
 * The heavy three.js/vanta code is dynamically imported so it never blocks
 * or breaks the initial page load: if WebGL is unavailable or the import
 * fails, the static background simply remains. Disabled for reduced-motion
 * and touch pointers.
 */
export function VantaNet({
  className = '',
  backgroundColor = 0xedf1f7,
  color = 0x06b6d4,
}: {
  className?: string;
  /** Page background the canvas blends into (three.js hex). */
  backgroundColor?: number;
  /** Network line/dot color (three.js hex). */
  color?: number;
}) {
  const hostRef = useRef<HTMLDivElement>(null);
  const vantaRef = useRef<VantaNetInstance | null>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host || vantaRef.current) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (window.matchMedia('(pointer: coarse)').matches) return;

    let cancelled = false;

    (async () => {
      try {
        const [vantaMod, THREE] = await Promise.all([
          import('vanta/dist/vanta.net.min'),
          import('three'),
        ]);
        // The UMD build's export shape varies by bundler interop: the factory
        // may sit at mod.default or one level deeper at mod.default.default.
        const exported = (vantaMod as unknown as { default?: unknown }).default as
          | ((opts: Record<string, unknown>) => VantaNetInstance)
          | { default?: (opts: Record<string, unknown>) => VantaNetInstance }
          | undefined;
        const NET =
          typeof exported === 'function' ? exported : exported?.default;
        if (typeof NET !== 'function') {
          throw new Error('Vanta NET factory not found in module exports');
        }
        if (cancelled || vantaRef.current || !hostRef.current) return;
        vantaRef.current = NET({
          el: hostRef.current,
          THREE,
          mouseControls: true,
          touchControls: false,
          gyroControls: false,
          minHeight: 200.0,
          minWidth: 200.0,
          scale: 1.0,
          scaleMobile: 1.0,
          backgroundColor,
          color,
          points: 9.0,
          maxDistance: 26.0,
          spacing: 22.0,
          showDots: true,
        });
        hostRef.current.style.opacity = '1';
      } catch {
        // Keep the static background — the animation must never break the page.
      }
    })();

    return () => {
      cancelled = true;
      vantaRef.current?.destroy();
      vantaRef.current = null;
    };
  }, []);

  return (
    <div
      ref={hostRef}
      aria-hidden="true"
      style={{ opacity: 0 }}
      className={`pointer-events-none absolute inset-0 transition-opacity duration-1000 [mask-image:linear-gradient(to_bottom,black_0%,black_52%,transparent_88%)] ${className}`}
    />
  );
}
