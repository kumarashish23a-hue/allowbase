import { useEffect, useRef } from 'react';

/**
 * A soft cyan glow that follows the cursor inside its container.
 * Smooth trailing via rAF lerp, transform-only updates, paused off-screen,
 * disabled for reduced-motion and touch pointers.
 */
export function CursorGlow({ className = '' }: { className?: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const glowRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    const glow = glowRef.current;
    if (!container || !glow) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (window.matchMedia('(pointer: coarse)').matches) return;

    const target = { x: 0, y: 0 };
    const current = { x: 0, y: 0 };
    let entered = false;
    let running = true;
    let raf = 0;

    const onMove = (event: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      target.x = event.clientX - rect.left;
      target.y = event.clientY - rect.top;
      if (!entered) {
        entered = true;
        current.x = target.x;
        current.y = target.y;
        glow.style.opacity = '1';
      }
    };

    const onLeave = () => {
      entered = false;
      glow.style.opacity = '0';
    };

    const tick = () => {
      if (!running) return;
      current.x += (target.x - current.x) * 0.08;
      current.y += (target.y - current.y) * 0.08;
      glow.style.transform = `translate3d(${current.x}px, ${current.y}px, 0)`;
      raf = requestAnimationFrame(tick);
    };

    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !running) {
        running = true;
        raf = requestAnimationFrame(tick);
      } else if (!entry.isIntersecting && running) {
        running = false;
        cancelAnimationFrame(raf);
      }
    });
    observer.observe(container);

    container.addEventListener('mousemove', onMove);
    container.addEventListener('mouseleave', onLeave);
    raf = requestAnimationFrame(tick);

    return () => {
      running = false;
      cancelAnimationFrame(raf);
      observer.disconnect();
      container.removeEventListener('mousemove', onMove);
      container.removeEventListener('mouseleave', onLeave);
    };
  }, []);

  return (
    <div
      ref={containerRef}
      aria-hidden="true"
      className={`pointer-events-none absolute inset-0 overflow-hidden ${className}`}
    >
      <div
        ref={glowRef}
        className="absolute left-0 top-0 h-[560px] w-[560px] opacity-0 transition-opacity duration-500"
        style={{
          marginLeft: -280,
          marginTop: -280,
          background:
            'radial-gradient(circle, rgba(34,211,238,0.2) 0%, rgba(34,211,238,0.07) 40%, transparent 65%)',
        }}
      />
    </div>
  );
}
