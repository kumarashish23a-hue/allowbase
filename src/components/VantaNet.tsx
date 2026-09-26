import { useEffect, useRef } from 'react';

interface VantaNetInstance {
  destroy: () => void;
}

/**
 * Interactive Vanta.js NET backdrop: a living network of nodes and links
 * that reacts to the cursor. Customized for the light theme — cyan net on
 * the page background, airy spacing, faded out toward the bottom so content
 * below the hero fold stays clean.
 *
 * The heavy three.js/vanta code is dynamically imported so it never blocks
 * or breaks the initial page load: if WebGL is unavailable or the import
 * fails, the static background simply remains. Disabled for reduced-motion
 * and touch pointers.
 */
export function VantaNet({ className = '' }: { className?: string }) {
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
        const [{ default: NET }, THREE] = await Promise.all([
          import('vanta/dist/vanta.net.min'),
          import('three'),
        ]);
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
          backgroundColor: 0xedf1f7,
          color: 0x06b6d4,
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
