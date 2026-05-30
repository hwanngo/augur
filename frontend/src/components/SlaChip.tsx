import { useTranslation } from 'react-i18next';

interface Props {
  createdAt: string;
  resolvedAt?: string | null;
  status: string;
}

type Band = 'green' | 'amber' | 'red';

const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

const AMBER_MS = 4 * HOUR;
const RED_MS = 24 * HOUR;

const TERMINAL = new Set(['resolved', 'closed']);

const BAND_COLORS: Record<Band, { bg: string; fg: string }> = {
  green: { bg: 'var(--ok-bg, rgba(34,197,94,0.15))', fg: 'var(--ok, #16a34a)' },
  amber: { bg: 'var(--warn-bg, rgba(245,158,11,0.15))', fg: 'var(--warn, #d97706)' },
  red: { bg: 'var(--danger-bg, rgba(239,68,68,0.15))', fg: 'var(--danger, #dc2626)' },
};

/** Short humanized age: "5m" / "3h" / "2d" (largest non-zero unit, floored). */
function humanize(ms: number): string {
  const clamped = Math.max(0, ms);
  if (clamped >= DAY) return `${Math.floor(clamped / DAY)}d`;
  if (clamped >= HOUR) return `${Math.floor(clamped / HOUR)}h`;
  if (clamped >= MIN) return `${Math.floor(clamped / MIN)}m`;
  return '0m';
}

function bandFor(ms: number): Band {
  if (ms < AMBER_MS) return 'green';
  if (ms < RED_MS) return 'amber';
  return 'red';
}

/**
 * Per-alert age / SLA indicator. Shows the time the alert has been open, colour-banded by age.
 * For terminal statuses (resolved/closed) with a `resolvedAt`, the age freezes at resolution.
 */
export default function SlaChip({ createdAt, resolvedAt, status }: Props) {
  const { t } = useTranslation();
  const created = new Date(createdAt).getTime();
  const frozen = TERMINAL.has(status) && resolvedAt ? new Date(resolvedAt).getTime() : null;
  const end = frozen !== null && !Number.isNaN(frozen) ? frozen : Date.now();
  const ageMs = end - created;
  const duration = humanize(ageMs);
  const band = bandFor(ageMs);
  const { bg, fg } = BAND_COLORS[band];

  const ariaLabel =
    frozen !== null
      ? t('alerts.sla.resolvedIn', { duration })
      : t('alerts.sla.label', { duration });

  return (
    <span
      data-band={band}
      aria-label={ariaLabel}
      title={ariaLabel}
      className="inline-flex items-center px-1.5 py-0.5 rounded-md text-xs font-medium tabular-nums"
      style={{ background: bg, color: fg }}
    >
      {duration}
    </span>
  );
}
