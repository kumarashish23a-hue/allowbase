import { useEffect, useRef } from 'react';
import * as THREE from 'three';
import NET from 'vanta/dist/vanta.net.min';

interface VantaNetInstance {
  destroy: () => void;
}

/**
 * Interactive Vanta.js NET backdrop: a living network of nodes and links
 * that reacts to the cursor. Customized for the light theme — cyan net on
 * the page background, airy spacing, faded out toward the bottom so content
 * below the hero fold stays clean. Disabled for reduced-motion / touch.
 */
export function VantaNet({ className = '' }: { className?: string }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const vantaRef = useRef<VantaNetInstance | null>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host || vantaRef.current) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (window.matchMedia('(pointer: coarse)').matches) return;

    vantaRef.current = NET({
      el: host,
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

    return () => {
      vantaRef.current?.destroy();
      vantaRef.current = null;
    };
  }, []);

  return (
    <div
      ref={hostRef}
      aria-hidden="true"
      className={`pointer-events-none absolute inset-0 [mask-image:linear-gradient(to_bottom,black_0%,black_52%,transparent_88%)] ${className}`}
    />
  );
}
