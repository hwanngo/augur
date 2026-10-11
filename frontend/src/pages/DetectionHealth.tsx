import { useEffect, useState } from 'react';
import { Activity, AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, ApiError } from '../lib/api';
import DetailDrawer from '../components/DetailDrawer';
import { CritChip, toCrit } from '../lib/criticality';

/* ──────────────────────────── Types ─────────────────────────────────────── */
type HealthState = 'FIRING' | 'PARTIAL' | 'SILENT' | 'NEVER';

interface ScenarioRow {
  scenario_id: string;
  name: string;
  severity: string;
  os_family: string;
  tactics: string[];
  state: HealthState;
  max_proximity: number;
  fire_count: number;
  last_fired: string | null;
  affected_host_count: number;
}

interface HealthSummary {
  scenarios_total: number;
  by_state: Record<HealthState, number>;
  corpus_span: { from: string | null; to: string | null };
  sweep_buckets: number;
  honesty_note: string;
}

interface HealthResult {
  summary: HealthSummary;
  scenarios: ScenarioRow[];
}

const STATE_STYLE: Record<HealthState, { bg: string; fg: string }> = {
  FIRING:  { bg: '#1d3a26', fg: '#7ee2a8' },
  PARTIAL: { bg: '#7a4a00', fg: '#ffd28a' },
  SILENT:  { bg: '#23364a', fg: '#9fc7ef' },
  NEVER:   { bg: '#71221c', fg: '#ffb4ab' },
};

const STATE_ORDER: HealthState[] = ['FIRING', 'PARTIAL', 'SILENT', 'NEVER'];

function StateChip({ state }: { state: HealthState }) {
  const { t } = useTranslation();
  const { bg, fg } = STATE_STYLE[state];
  // "Silent"/"Never" carry honest hover/aria text; "Firing"/"Partial" do not.
  const aria = state === 'SILENT' || state === 'NEVER'
    ? t(`detectionHealth.stateAria.${state}`) : undefined;
  return (
    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide"
          style={{ background: bg, color: fg }}
          title={aria} aria-label={aria}>
      {t(`detectionHealth.states.${state}`)}
    </span>
  );
}

/* ──────────────────────────── Page ──────────────────────────────────────── */
export default function DetectionHealth() {
  const { t } = useTranslation();
  const [data, setData] = useState<HealthResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drawerRow, setDrawerRow] = useState<ScenarioRow | null>(null);

  useEffect(() => {
    apiGet<HealthResult>('/api/detection_health')
      .then((d) => { setData(d); setLoading(false); })
      .catch((e: unknown) => {
        setError(e instanceof ApiError ? e.message : t('detectionHealth.failed'));
        setLoading(false);
      });
  }, [t]);

  return (
    <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Activity size={18} aria-hidden /> {t('detectionHealth.title')}
        </h1>
        <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{t('detectionHealth.subtitle')}</p>
      </div>

      {/* Persistent honesty panel — renders the API-supplied note verbatim. */}
      <p className="rounded-xl border p-3 text-xs italic flex items-start gap-2"
         style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--muted)' }}>
        <AlertTriangle size={14} aria-hidden style={{ flexShrink: 0, marginTop: 1 }} />
        {data ? data.summary.honesty_note : t('detectionHealth.honesty')}
      </p>

      {error && (
        <div className="rounded-xl border p-3 flex items-center gap-2 text-sm" role="alert"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}>
          <AlertTriangle size={14} aria-hidden /> {error}
        </div>
      )}

      {loading && <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('detectionHealth.loading')}</p>}

      {data && !loading && (
        <div className="space-y-3">
          {/* Summary strip: state chips + counts, span. */}
          <div className="flex flex-wrap items-center gap-3 text-xs" style={{ color: 'var(--muted)' }}>
            <span className="flex flex-wrap items-center gap-2">
              {STATE_ORDER.map((st) => (
                <span key={st} className="flex items-center gap-1">
                  <StateChip state={st} />
                  <span className="tabular-nums">{data.summary.by_state[st]}</span>
                </span>
              ))}
            </span>
            <span className="tabular-nums">
              {data.summary.corpus_span.from && data.summary.corpus_span.to
                ? t('detectionHealth.span', { from: data.summary.corpus_span.from, to: data.summary.corpus_span.to })
                : t('detectionHealth.spanEmpty')}
            </span>
          </div>

          {data.scenarios.length === 0 ? (
            <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{t('detectionHealth.empty')}</p>
          ) : (
            <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
              <table className="w-full min-w-[760px] text-xs">
                <thead style={{ background: 'var(--panel)' }}>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('detectionHealth.cols.scenario')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('detectionHealth.cols.state')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('detectionHealth.cols.proximity')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('detectionHealth.cols.fireCount')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('detectionHealth.cols.lastFired')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('detectionHealth.cols.hosts')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('detectionHealth.cols.severity')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('detectionHealth.cols.os')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.scenarios.map((r) => (
                    <tr key={r.scenario_id}
                        role="button"
                        tabIndex={0}
                        aria-label={t('detectionHealth.inspectRow', { id: r.scenario_id })}
                        onClick={() => setDrawerRow(r)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            if (e.key === ' ') e.preventDefault();
                            setDrawerRow(r);
                          }
                        }}
                        className="cursor-pointer hover:bg-panel focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                        style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-3 py-1.5">
                        <div className="font-mono" style={{ color: 'var(--fg)' }}>{r.scenario_id}</div>
                        <div style={{ color: 'var(--muted)' }}>{r.name}</div>
                      </td>
                      <td className="px-3 py-1.5"><StateChip state={r.state} /></td>
                      <td className="px-3 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{r.max_proximity}</td>
                      <td className="px-3 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{r.fire_count}</td>
                      <td className="px-3 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{r.last_fired ?? '—'}</td>
                      <td className="px-3 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{r.affected_host_count}</td>
                      <td className="px-3 py-1.5 uppercase" style={{ color: 'var(--muted)' }}>{r.severity}</td>
                      <td className="px-3 py-1.5" style={{ color: 'var(--muted)' }}>{r.os_family}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Row drill */}
      <DetailDrawer open={drawerRow != null} title={drawerRow?.scenario_id ?? ''} onClose={() => setDrawerRow(null)}>
        {drawerRow && (
          <div className="space-y-4 text-xs">
            <div style={{ color: 'var(--fg)' }}>{drawerRow.name}</div>
            <div className="flex items-center gap-2">
              <StateChip state={drawerRow.state} />
              <CritChip level={toCrit(drawerRow.severity)} />
              <span style={{ color: 'var(--muted)' }}>{drawerRow.os_family}</span>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('detectionHealth.drawer.maxProximity')}</div>
                <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>{drawerRow.max_proximity}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('detectionHealth.drawer.fireCount')}</div>
                <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>{drawerRow.fire_count}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('detectionHealth.drawer.lastFired')}</div>
                <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>
                  {drawerRow.last_fired ?? t('detectionHealth.drawer.never')}
                </div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('detectionHealth.drawer.hosts')}</div>
                <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>{drawerRow.affected_host_count}</div>
              </div>
            </div>
            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>{t('detectionHealth.drawer.tactics')}</div>
              <div className="flex flex-wrap gap-1">
                {drawerRow.tactics.map((ta) => (
                  <span key={ta} className="px-2 py-0.5 rounded-full text-[10px] font-mono"
                        style={{ background: 'var(--panel)', color: 'var(--fg)' }}>{ta}</span>
                ))}
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
