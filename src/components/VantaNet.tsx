import type { CSSProperties } from 'react';

function toHex(value: number): string {
  return `#${value.toString(16).padStart(6, '0')}`;
}

/**
 * Lightweight ambient hero backdrop.
 *
 * This used to rely on Vanta/WebGL for an interactive node network. The CSS
 * version keeps the same theme-aware API but avoids a large Three.js canvas,
 * GPU spikes, and a blank hero on devices where WebGL is unavailable.
 */
export function VantaNet({
  className = '',
  backgroundColor = 0xedf1f7,
  color = 0x06b6d4,
}: {
  className?: string;
  /** Base color the backdrop blends into. */
  backgroundColor?: number;
  /** Accent color for the ambient light and grid. */
  color?: number;
}) {
  const style = {
    '--ambient-base': toHex(backgroundColor),
    '--ambient-accent': toHex(color),
  } as CSSProperties;

  return (
    <div
      aria-hidden="true"
      style={style}
      className={`ambient-backdrop pointer-events-none absolute inset-0 overflow-hidden ${className}`}
    >
      <div className="ambient-backdrop__wash" />
      <div className="ambient-backdrop__orb ambient-backdrop__orb--primary" />
      <div className="ambient-backdrop__orb ambient-backdrop__orb--secondary" />
      <div className="ambient-backdrop__grid" />
      <div className="ambient-backdrop__horizon" />
    </div>
  );
}
