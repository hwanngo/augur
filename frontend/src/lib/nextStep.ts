/**
 * Read-only criteria → human-readable text formatting for F1 "next-step hunting".
 *
 * Turns a missing step's `matching_criteria` dict + serialized `temporal` link into
 * analyst-facing guidance ("look for `field op value`; within ≤Ns of the prior step, same host").
 * Pure functions — no side effects, no engine logic.
 */

export interface Temporal {
  previous_step: number;
  link_scope: 'same_host' | 'cross_host' | 'any';
  min_time_delta_seconds: number;
  max_time_delta_seconds: number;
}

export interface MissingStep {
  step_id: number;
  name: string;
  matching_criteria?: Record<string, unknown>;
  temporal?: Temporal | null;
}

const SKIP = new Set(['Node_Type']);

function formatValue(v: unknown): string {
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    if ('in' in o) return `in [${(o.in as unknown[]).join(', ')}]`;
    if ('equals' in o) return `= ${String(o.equals)}`;
    if ('regex' in o) return `~ ${String(o.regex)}`;
    if ('exists' in o) return o.exists ? 'is present' : 'is absent';
  }
  return `= ${String(v)}`;
}

export function formatCriteria(criteria?: Record<string, unknown>): string {
  if (!criteria) return '';
  return Object.entries(criteria)
    .filter(([k]) => !SKIP.has(k))
    .map(([k, v]) => `${k} ${formatValue(v)}`)
    .join('; ');
}

const SCOPE_TEXT: Record<Temporal['link_scope'], string> = {
  same_host: 'same host',
  cross_host: 'a different host',
  any: 'any host',
};

export function formatTemporal(t?: Temporal | null): string | null {
  if (!t) return null;
  return `within ≤${t.max_time_delta_seconds}s of the prior step, ${SCOPE_TEXT[t.link_scope]}`;
}

/**
 * F3 "why it stalled" near-miss diagnosis (emitted by `engine/diagnose.py`).
 * Discriminated union mirroring the backend `stall` dict, present only on sub-100% detections.
 */
export type Stall =
  | { kind: 'no_candidate'; step_id: number; step_name: string }
  | { kind: 'temporal'; step_id: number; host: string | null; delta_seconds: number; window_seconds: number }
  | { kind: 'spatial'; step_id: number; host: string | null; zone: string | null; applicable_zones: string[] }
  | { kind: 'link'; step_id: number; host: string | null; link_scope: string };

/** Render a `stall` dict into a single human-readable near-miss explanation. */
export function formatStall(s: Stall): string {
  switch (s.kind) {
    case 'no_candidate':
      return `no event matching "${s.step_name}" was seen`;
    case 'temporal':
      return `closest candidate on ${s.host ?? '?'} fell outside the ${s.window_seconds}s window (Δ${Math.round(s.delta_seconds)}s)`;
    case 'spatial':
      return `candidate host ${s.host ?? '?'} is in ${s.zone ?? '?'}, not an applicable zone (${s.applicable_zones.join(', ')})`;
    case 'link':
      return `candidate is cross-host but the step requires ${s.link_scope}`;
  }
}
