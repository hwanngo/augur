import { useState } from 'react';
import { Check, Circle, Copy, ChevronDown, ChevronRight, AlertTriangle, ExternalLink, Send, X, GitFork } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { formatCriteria, formatTemporal, formatStall, type Temporal, type Stall } from '../lib/nextStep';
import { apiGet, apiPost } from '../lib/api';

/* ──────────────────────────── Types ─────────────────────────────────────── */
interface MatchedStep {
  step_id: number;
  name: string;
  host: string;
  timestamp?: string | null;
}
interface MissingStep {
  step_id: number;
  name: string;
  matching_criteria?: Record<string, unknown>;
  temporal?: Temporal | null;
}
interface HuntingQuery {
  engine: string;
  query?: string;
  query_path?: string;
}
export interface Momentum {
  points: number[];
  trend: 'rising' | 'flat' | 'falling';
  delta: number;
  velocity: number;
}
interface Playbook {
  scenario_id: string;
  label: string;
  derived_from: { tactic: string; tactic_name: string; severity: string };
  sections: {
    contain: string[];
    eradicate: string[];
    recover: string[];
    validate: HuntingQuery[];
  };
}
interface DispatchResult {
  ok: boolean;
  sink: string;
  payload: unknown;
}
export interface Detection {
  scenario_id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  proximity: number;
  matched_steps: MatchedStep[];
  missing_steps: MissingStep[];
  affected_hosts: string[];
  affected_zones: string[];
  hunting_queries: HuntingQuery[];
  stall?: Stall;
  momentum?: Momentum;
}

/* ──────────────────────────── Severity chip ─────────────────────────────── */
const SEV_STYLE: Record<Detection['severity'], { bg: string; fg: string }> = {
  CRITICAL: { bg: '#71221c', fg: '#ffb4ab' },
  HIGH:     { bg: '#7a4a00', fg: '#ffd28a' },
  MEDIUM:   { bg: '#39402a', fg: '#d8e08a' },
  LOW:      { bg: '#23364a', fg: '#9fc7ef' },
};

export function SevChip({ level }: { level: Detection['severity'] }) {
  const { bg, fg } = SEV_STYLE[level];
  return (
    <span
      className="px-2 py-0.5 rounded-full text-xs font-bold tabular-nums uppercase tracking-wide shrink-0"
      style={{ background: bg, color: fg }}
      aria-label={`Severity: ${level}`}
    >
      {level}
    </span>
  );
}

/* ──────────────────────────── Copy button ───────────────────────────────── */
function CopyButton({ text }: { text: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  };
  return (
    <button
      type="button"
      onClick={handleCopy}
      className="btn-ghost px-2 py-1 text-xs flex items-center gap-1"
      aria-label={copied ? t('dashboard.copied') : t('dashboard.copyToClipboard')}
    >
      {copied ? <Check size={12} aria-hidden /> : <Copy size={12} aria-hidden />}
      {copied ? t('dashboard.copied') : t('dashboard.copy')}
    </button>
  );
}

/* ──────────────────────────── Momentum badge ────────────────────────────── */
const MOM_STYLE = {
  rising:  { arrow: '▲', color: '#3fb950' },      // ▲ green
  flat:    { arrow: '▬', color: 'var(--muted)' }, // ▬ grey
  falling: { arrow: '▼', color: '#ffd28a' },      // ▼ amber
} as const;

function MomentumBadge({ m }: { m: Momentum }) {
  const { t } = useTranslation();
  const { arrow, color } = MOM_STYLE[m.trend];
  const pts = m.points;
  const max = Math.max(...pts, 1);                 // proximity is 0..1; guard /0
  const W = 56, H = 16;
  const poly = pts
    .map((p, i) => `${(pts.length === 1 ? 0 : (i / (pts.length - 1)) * W).toFixed(1)},${(H - (p / max) * H).toFixed(1)}`)
    .join(' ');
  const pct = Math.round(m.delta * 100);
  return (
    <span className="flex items-center gap-1.5 text-xs tabular-nums" title={t(`dashboard.momentum.${m.trend}`)}>
      <span style={{ color }} aria-label={t('dashboard.momentum.label', { trend: t(`dashboard.momentum.${m.trend}`) })}>
        {arrow}
      </span>
      <svg data-testid="momentum-spark" width={W} height={H} viewBox={`0 0 ${W} ${H}`} aria-hidden role="img">
        <polyline points={poly} fill="none" stroke={color} strokeWidth={1.5} />
      </svg>
      <span style={{ color }}>{pct >= 0 ? `+${pct}` : pct}%</span>
    </span>
  );
}

/* ──────────────────────────── Hunting-query block ───────────────────────── */
function QueryBlock({ q }: { q: HuntingQuery }) {
  const text = q.query ?? q.query_path ?? '';
  return (
    <div
      className="rounded-lg border p-3 space-y-2"
      style={{ background: 'var(--bg)', borderColor: 'var(--border)' }}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-widest" style={{ color: 'var(--muted)' }}>
          {q.engine}
        </span>
        <CopyButton text={text} />
      </div>
      <pre className="text-xs whitespace-pre-wrap break-all font-mono" style={{ color: 'var(--fg)', margin: 0 }}>
        {text}
      </pre>
    </div>
  );
}

/* ──────────────────────────── Detection card ────────────────────────────── */
export default function DetectionCard({
  d,
  onOpenCase,
  onPivot,
  showPlaybook = false,
}: {
  d: Detection;
  onOpenCase: (d: Detection) => void;
  onPivot?: (d: Detection) => void;
  showPlaybook?: boolean;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [pbOpen, setPbOpen] = useState(false);
  const [pb, setPb] = useState<Playbook | null>(null);
  const [dispatched, setDispatched] = useState<DispatchResult | null>(null);
  const [dispatchError, setDispatchError] = useState(false);

  const togglePlaybook = () => {
    setPbOpen((o) => !o);
    if (!pb) {
      void apiGet<Playbook>('/api/playbook?scenario_id=' + encodeURIComponent(d.scenario_id))
        .then(setPb)
        .catch(() => {});
    }
  };

  const dispatch = () => {
    setDispatchError(false);
    void apiPost<DispatchResult>('/api/dispatch', { scenario_id: d.scenario_id })
      .then(setDispatched)
      .catch(() => setDispatchError(true));
  };

  const pct = Math.round(d.proximity * 100);
  const matched = d.matched_steps.length;
  const total = matched + d.missing_steps.length;
  const { bg: sevBg } = SEV_STYLE[d.severity];

  return (
    <div
      className="rounded-xl border p-4 space-y-3 transition-shadow duration-200 hover:shadow-lg"
      style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
    >
      {/* Header row */}
      <div className="flex items-center gap-3 flex-wrap">
        <SevChip level={d.severity} />
        <span className="font-semibold text-sm flex-1 min-w-0 truncate" style={{ color: 'var(--fg)' }}>
          {d.name}
        </span>
        <div className="flex items-center gap-2 shrink-0">
          {d.momentum && <MomentumBadge m={d.momentum} />}
          {/* Proximity bar */}
          <div
            className="w-32 h-2 rounded-full overflow-hidden shrink-0"
            style={{ background: 'var(--border)' }}
            role="progressbar"
            aria-valuenow={pct}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={`Proximity ${pct}%`}
          >
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{ width: `${pct}%`, background: sevBg !== '#23364a' ? 'var(--accent)' : '#9fc7ef' }}
            />
          </div>
          <span className="text-sm font-bold tabular-nums" style={{ color: 'var(--fg)' }}>
            {matched}/{total} &bull; {pct}%
          </span>
          <button
            type="button"
            onClick={() => onOpenCase(d)}
            className="btn-ghost px-2 py-1 text-xs flex items-center gap-1 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
            aria-label={t('dashboard.openCase')}
          >
            <ExternalLink size={12} aria-hidden />
            {t('dashboard.openCase')}
          </button>
          <button
            type="button"
            onClick={() => onPivot?.(d)}
            className="btn-ghost px-2 py-1 text-xs flex items-center gap-1 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
            aria-label={t('dashboard.pivot')}
          >
            <GitFork size={12} aria-hidden />
            {t('dashboard.pivot')}
          </button>
        </div>
      </div>

      {/* Meta */}
      <div className="text-xs space-x-2" style={{ color: 'var(--muted)' }}>
        <span>{d.scenario_id}</span>
        <span>&bull;</span>
        <span>hosts: {d.affected_hosts.join(', ')}</span>
        <span>&bull;</span>
        <span>zones: {d.affected_zones.join(', ')}</span>
      </div>

      {/* F3 — "why it stalled" near-miss line (partial detections only) */}
      {d.stall && (
        <div className="flex items-start gap-2 text-xs" style={{ color: 'var(--muted)' }}>
          <AlertTriangle size={12} className="mt-0.5 shrink-0" aria-hidden />
          <span>{t('dashboard.whyStalled', { reason: formatStall(d.stall) })}</span>
        </div>
      )}

      {/* Expandable steps + queries */}
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 text-xs transition-colors duration-150 cursor-pointer"
        style={{ color: 'var(--muted)' }}
        aria-expanded={open}
      >
        {open ? <ChevronDown size={13} aria-hidden /> : <ChevronRight size={13} aria-hidden />}
        {t('dashboard.stepsAndQueries')}
      </button>

      {open && (
        <div className="space-y-3 pt-1">
          {/* Steps */}
          <ul className="space-y-1 text-xs">
            {d.matched_steps.map((s) => (
              <li key={s.step_id} className="flex items-start gap-2" style={{ color: 'var(--accent)' }}>
                <Check size={12} className="mt-0.5 shrink-0" aria-hidden />
                <span>
                  <span className="font-medium tabular-nums">{s.step_id}.</span> {s.name}
                  {s.host && (
                    <span style={{ color: 'var(--muted)' }}>
                      {' '}@{s.host}{s.timestamp ? ` ${s.timestamp}` : ''}
                    </span>
                  )}
                </span>
              </li>
            ))}
            {d.missing_steps.map((s) => {
              const criteria = formatCriteria(s.matching_criteria);
              const temporal = formatTemporal(s.temporal);
              const hasGuidance = criteria !== '' || temporal !== null;
              return (
                <li key={s.step_id} className="flex items-start gap-2" style={{ color: 'var(--muted)' }}>
                  <Circle size={12} className="mt-0.5 shrink-0" aria-hidden />
                  <span>
                    <span className="font-medium tabular-nums">{s.step_id}.</span> {s.name}
                    {hasGuidance && (
                      <span className="block mt-0.5" style={{ color: 'var(--muted)' }}>
                        {t('dashboard.nextStep', { name: s.name })}
                        {criteria !== '' && <> — {t('dashboard.lookFor', { criteria })}</>}
                        {temporal !== null && <>; {temporal}</>}
                      </span>
                    )}
                  </span>
                </li>
              );
            })}
          </ul>

          {/* Hunting queries */}
          {d.hunting_queries.map((q, i) => (
            <QueryBlock key={i} q={q} />
          ))}
        </div>
      )}

      {/* Response playbook (opt-in via showPlaybook) */}
      {showPlaybook && (
        <>
          <button
            type="button"
            onClick={togglePlaybook}
            className="flex items-center gap-1 text-xs transition-colors duration-150 cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
            style={{ color: 'var(--muted)' }}
            aria-expanded={pbOpen}
          >
            {pbOpen ? <ChevronDown size={13} aria-hidden /> : <ChevronRight size={13} aria-hidden />}
            {t('dashboard.playbook.title')}
          </button>

          {pbOpen && pb && (
            <div className="space-y-3 pt-1">
              <div>
                <div className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
                  {pb.label}
                </div>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>
                  {t('dashboard.playbook.standardLabel')}
                </div>
              </div>

              {(['contain', 'eradicate', 'recover'] as const).map((section) => (
                <div key={section} className="space-y-1">
                  <div
                    className="text-xs font-medium uppercase tracking-widest"
                    style={{ color: 'var(--muted)' }}
                  >
                    {t(`dashboard.playbook.${section}`)}
                  </div>
                  <ol className="list-decimal list-inside space-y-0.5 text-xs" style={{ color: 'var(--fg)' }}>
                    {pb.sections[section].map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </div>
              ))}

              {pb.sections.validate.length > 0 && (
                <div className="space-y-1">
                  <div
                    className="text-xs font-medium uppercase tracking-widest"
                    style={{ color: 'var(--muted)' }}
                  >
                    {t('dashboard.playbook.validate')}
                  </div>
                  <div className="space-y-2">
                    {pb.sections.validate.map((q, i) => (
                      <QueryBlock key={i} q={q} />
                    ))}
                  </div>
                </div>
              )}

              <button
                type="button"
                onClick={dispatch}
                className="btn-ghost px-2 py-1 text-xs flex items-center gap-1 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                aria-label={t('dashboard.playbook.dispatch')}
              >
                <Send size={12} aria-hidden />
                {t('dashboard.playbook.dispatch')}
              </button>

              {dispatchError && (
                <div className="text-xs" style={{ color: '#ffb4ab' }} role="alert">
                  {t('dashboard.playbook.dispatchFailed')}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Dispatch preview modal */}
      {dispatched && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.6)' }}
          // Presentational backdrop: click or Escape dismisses. The dialog semantics live on the inner panel.
          onClick={() => setDispatched(null)}
          onKeyDown={(e) => { if (e.key === 'Escape') setDispatched(null); }}
          role="presentation"
        >
          {/* Dialog panel: onClick only stops the backdrop's dismiss; it is not an interactive control. */}
          {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-noninteractive-element-interactions */}
          <div
            className="rounded-xl border p-4 space-y-3 max-w-lg w-full max-h-[80vh] overflow-auto"
            style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
            role="dialog"
            aria-modal="true"
            aria-label={t('dashboard.playbook.previewTitle')}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between gap-3">
              <span className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
                {t('dashboard.playbook.previewTitle')}
              </span>
              <button
                type="button"
                onClick={() => setDispatched(null)}
                className="btn-ghost px-2 py-1 text-xs flex items-center gap-1 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                aria-label={t('common.closeDialog')}
              >
                <X size={12} aria-hidden />
              </button>
            </div>
            <div className="text-xs" style={{ color: 'var(--muted)' }}>
              {t('dashboard.playbook.dispatched')}
            </div>
            <pre
              className="text-xs whitespace-pre-wrap break-all font-mono rounded-lg border p-3"
              style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)', margin: 0 }}
            >
              {JSON.stringify(dispatched.payload, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
