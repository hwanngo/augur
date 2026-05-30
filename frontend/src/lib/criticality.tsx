/* Shared criticality vocabulary + chip — single source of truth for the
   asset-criticality scale used by Host Risk, Topology, and the Intel overlay. */

export type Crit = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export const CRIT_STYLE: Record<Crit, { bg: string; fg: string }> = {
  CRITICAL: { bg: '#71221c', fg: '#ffb4ab' },
  HIGH:     { bg: '#7a4a00', fg: '#ffd28a' },
  MEDIUM:   { bg: '#39402a', fg: '#d8e08a' },
  LOW:      { bg: '#23364a', fg: '#9fc7ef' },
  UNKNOWN:  { bg: '#21262d', fg: '#8b949e' },
};

/** Normalize an arbitrary criticality string to a known Crit (defaults to UNKNOWN). */
export function toCrit(c: string): Crit {
  const up = c.toUpperCase();
  return (up in CRIT_STYLE ? up : 'UNKNOWN') as Crit;
}

export function CritChip({ level }: { level: Crit }) {
  const { bg, fg } = CRIT_STYLE[level];
  return (
    <span
      className="px-2 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide"
      style={{ background: bg, color: fg }}
    >
      {level}
    </span>
  );
}
