import { useEffect, useState } from 'react';
import { AlertTriangle, ClipboardCheck, Crosshair, Info } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { apiGet, ApiError } from '../lib/api';
import ExportCsvButton from '../components/ExportCsvButton';
import Dropdown from '../components/Dropdown';
import DetailDrawer from '../components/DetailDrawer';
import { toCsv, downloadCsv, dateStamp, type CsvColumn } from '../lib/csv';

/* ──────────────────────────── Types ─────────────────────────────────────── */
type RowStatus = 'detected' | 'missed' | 'no_eligible_host' | 'error';

interface FeedSummary { total_events: number; baseline_events: number; injected_events: number }
interface CampaignRow {
  scenario_id: string;
  name: string;
  tactic: string;
  technique: string;
  os_family: string;
  host: string | null;
  status: RowStatus;
  detected: boolean;
  proximity: number;
  matched_steps: number;
  total_steps: number;
  feed_summary: FeedSummary | null;
  note: string | null;
}
interface CampaignDefinition {
  selector: 'scenario_ids' | 'tactic' | 'os_family' | 'all';
  selector_value: unknown;
  min_proximity: number;
  scenario_count: number;
}
interface CampaignAggregate {
  runnable: number;
  detected: number;
  missed: number;
  no_eligible_host: number;
  errors: number;
  pct_detected: number;
  gaps_by_tactic: Record<string, string[]>;
  no_eligible_host_scenarios: string[];
}
interface CampaignResponse {
  definition: CampaignDefinition;
  rows: CampaignRow[];
  aggregate: CampaignAggregate;
  honesty: string;
}

/* Status badge palette (per task spec). */
const STATUS_COLOR: Record<RowStatus, string> = {
  detected: '#7ee787',
  missed: '#ffb4ab',
  no_eligible_host: '#8b949e',
  error: '#ffd28a',
};

type OsOption = '' | 'windows' | 'linux' | 'macos';

/* ──────────────────────── CSV export columns ────────────────────────────── */
const EXPORT_COLUMNS: CsvColumn<CampaignRow>[] = [
  { header: 'scenario_id', value: (r) => r.scenario_id },
  { header: 'name', value: (r) => r.name },
  { header: 'tactic', value: (r) => r.tactic },
  { header: 'technique', value: (r) => r.technique },
  { header: 'host', value: (r) => r.host ?? '' },
  { header: 'status', value: (r) => r.status },
  { header: 'detected', value: (r) => String(r.detected) },
  { header: 'proximity', value: (r) => String(r.proximity) },
  { header: 'matched_steps', value: (r) => String(r.matched_steps) },
  { header: 'total_steps', value: (r) => String(r.total_steps) },
];

/* ───────────────────────── Purple-Team Scorecard ─────────────────────────── */
export default function Campaign() {
  const { t } = useTranslation();
  const [osFamily, setOsFamily] = useState<OsOption>('');
  const [tactic, setTactic] = useState('');
  const [minProximity, setMinProximity] = useState('1.0');
  const [data, setData] = useState<CampaignResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [searchParams, setSearchParams] = useSearchParams();
  const selectedId = searchParams.get('scenario');
  const selectScenario = (id: string | null) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (id) next.set('scenario', id); else next.delete('scenario');
      return next;
    });
  };
  const selectedRow = data?.rows.find((r) => r.scenario_id === selectedId) ?? null;

  const run = (os: OsOption, tac: string, minProx: string) => {
    setLoading(true);
    setError(null);
    // Only ONE primary selector: tactic wins, else os_family, else none (=all).
    const qs = new URLSearchParams();
    const tacTrim = tac.trim();
    if (tacTrim) qs.set('tactic', tacTrim);
    else if (os) qs.set('os_family', os);
    const mp = minProx.trim();
    if (mp) qs.set('min_proximity', mp);
    const query = qs.toString();
    apiGet<CampaignResponse>(`/api/campaign${query ? `?${query}` : ''}`)
      .then((d) => { setData(d); setLoading(false); })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : t('campaign.failedLoad'));
        setLoading(false);
      });
  };

  // Auto-fetch the default "all" scorecard on mount.
  useEffect(() => {
    run('', '', '1.0');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onExport = () => {
    if (!data || data.rows.length === 0) return;
    downloadCsv(`augur-campaign-${dateStamp()}.csv`, toCsv(data.rows, EXPORT_COLUMNS));
  };

  const agg = data?.aggregate ?? null;
  const pct = agg ? Math.round(agg.pct_detected * 100) : 0;
  const gapTactics = agg ? Object.entries(agg.gaps_by_tactic) : [];
  const noHost = agg?.no_eligible_host_scenarios ?? [];

  return (
    <div className="w-full max-w-(--breakpoint-2xl) mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <ClipboardCheck size={18} aria-hidden /> {t('campaign.title')}
          </h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{t('campaign.subtitle')}</p>
        </div>
        {data && data.rows.length > 0 && (
          <ExportCsvButton onExport={onExport} label={t('campaign.export')} />
        )}
      </div>

      {/* Scope controls */}
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
          {t('campaign.osFamily')}
          <Dropdown
            aria-label={t('campaign.osFamily')}
            value={osFamily}
            onChange={(v) => setOsFamily(v as OsOption)}
            options={[
              { value: '', label: t('campaign.osAny') },
              { value: 'windows', label: 'windows' },
              { value: 'linux', label: 'linux' },
              { value: 'macos', label: 'macos' },
            ]}
          />
        </label>

        <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
          {t('campaign.tactic')}
          <input
            type="text"
            aria-label={t('campaign.tactic')}
            value={tactic}
            onChange={(e) => setTactic(e.target.value)}
            placeholder="TA0006"
            className="px-2.5 py-1.5 text-xs rounded-lg border w-28"
            style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
          />
        </label>

        <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
          {t('campaign.minProximity')}
          <input
            type="number"
            min="0"
            max="1"
            step="0.05"
            aria-label={t('campaign.minProximity')}
            value={minProximity}
            onChange={(e) => setMinProximity(e.target.value)}
            className="px-2.5 py-1.5 text-xs rounded-lg border w-24 tabular-nums"
            style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
          />
        </label>

        <button
          type="button"
          onClick={() => run(osFamily, tactic, minProximity)}
          disabled={loading}
          className="btn-primary px-3 py-1.5 text-xs rounded-lg flex items-center gap-2"
        >
          {loading && (
            <span
              className="w-3 h-3 rounded-full border-2 animate-spin"
              style={{ borderColor: 'rgba(0,0,0,0.25)', borderTopColor: '#0d1117' }}
              aria-hidden
            />
          )}
          {loading ? t('campaign.running') : t('campaign.run')}
        </button>
      </div>

      {loading && !data && !error && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('campaign.running')}
          />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>{t('campaign.running')}</span>
        </div>
      )}

      {error && (
        <div
          className="rounded-xl border p-4 flex items-center gap-3"
          style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}
          role="alert"
        >
          <AlertTriangle size={16} aria-hidden /> {error}
        </div>
      )}

      {!error && data && (
        <>
          {/* Aggregate header */}
          <div className="flex items-end gap-6 flex-wrap">
            <div>
              <div className="text-4xl font-bold tabular-nums" style={{ color: 'var(--fg)' }}>
                {t('campaign.pctDetected', { pct })}
              </div>
            </div>
            <div className="flex items-center gap-4 text-sm tabular-nums pb-1">
              <span style={{ color: '#7ee787' }}>{t('campaign.detected', { n: agg?.detected ?? 0 })}</span>
              <span style={{ color: '#ffb4ab' }}>{t('campaign.missed', { n: agg?.missed ?? 0 })}</span>
              <span style={{ color: '#8b949e' }}>{t('campaign.noHost', { n: agg?.no_eligible_host ?? 0 })}</span>
            </div>
          </div>

          {/* Honesty banner — persistent, brand-critical. */}
          <div
            className="rounded-xl border p-3 flex items-start gap-2 text-xs italic"
            style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--muted)' }}
          >
            <Info size={14} aria-hidden className="mt-0.5 shrink-0" />
            <span>{data.honesty}</span>
          </div>

          {data.rows.length === 0 ? (
            <div className="text-center py-16">
              <p className="text-sm" style={{ color: 'var(--muted)' }}>{t('campaign.empty')}</p>
            </div>
          ) : (
            <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
              <table className="w-full text-sm" aria-label={t('campaign.ariaLabel')}>
                <thead style={{ background: 'var(--panel)' }}>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>{t('campaign.col.scenario')}</th>
                    <th className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>{t('campaign.col.name')}</th>
                    <th className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>{t('campaign.col.tactic')}</th>
                    <th className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>{t('campaign.col.host')}</th>
                    <th className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>{t('campaign.col.status')}</th>
                    <th className="px-3 py-2.5 text-right text-xs font-medium" style={{ color: 'var(--muted)' }}>{t('campaign.col.proximity')}</th>
                    <th className="px-3 py-2.5 text-right text-xs font-medium" style={{ color: 'var(--muted)' }}>{t('campaign.col.steps')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.rows.map((r) => (
                    <tr
                      key={r.scenario_id}
                      style={{
                        borderBottom: '1px solid var(--border)',
                        background: selectedId === r.scenario_id ? '#1b2129' : undefined,
                      }}
                      className="transition-colors hover:bg-[#1e242c]"
                    >
                      <td className="px-3 py-2.5">
                        <button
                          type="button"
                          onClick={() => selectScenario(r.scenario_id)}
                          aria-current={selectedId === r.scenario_id}
                          aria-label={t('campaign.detail.open', { name: r.name })}
                          className="text-xs font-mono text-left cursor-pointer hover:underline focus:underline focus:outline-hidden"
                          style={{
                            color: 'var(--fg)',
                            boxShadow:
                              selectedId === r.scenario_id ? 'inset 2px 0 0 0 var(--accent)' : undefined,
                          }}
                        >
                          {r.scenario_id}
                        </button>
                      </td>
                      <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--fg)' }}>{r.name}</td>
                      <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--muted)' }}>{r.tactic}</td>
                      <td className="px-3 py-2.5 text-xs font-mono" style={{ color: 'var(--muted)' }}>{r.host ?? '—'}</td>
                      <td className="px-3 py-2.5">
                        <span
                          className="inline-block px-2 py-0.5 rounded-full text-xs font-bold"
                          style={{ background: 'rgba(255,255,255,0.04)', color: STATUS_COLOR[r.status] }}
                        >
                          {t(`campaign.status.${r.status}`)}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-xs text-right tabular-nums" style={{ color: 'var(--fg)' }}>{r.proximity.toFixed(2)}</td>
                      <td className="px-3 py-2.5 text-xs text-right tabular-nums" style={{ color: 'var(--muted)' }}>{r.matched_steps}/{r.total_steps}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Coverage / planning gaps — NOT detection misses. */}
          {(gapTactics.length > 0 || noHost.length > 0) && (
            <div
              className="rounded-xl border p-4 space-y-3"
              style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
            >
              <h2 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>{t('campaign.gaps.title')}</h2>
              <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{t('campaign.gaps.note')}</p>
              {gapTactics.length > 0 && (
                <div className="space-y-1.5">
                  {gapTactics.map(([tac, ids]) => (
                    <div key={tac} className="flex items-start gap-2 text-xs">
                      <span className="font-mono shrink-0" style={{ color: 'var(--fg)' }}>{tac}</span>
                      <span className="font-mono" style={{ color: '#ffb4ab' }}>{ids.join(', ')}</span>
                    </div>
                  ))}
                </div>
              )}
              {noHost.length > 0 && (
                <div className="text-xs">
                  <span style={{ color: 'var(--muted)' }}>{t('campaign.gaps.noHostHeading')}: </span>
                  <span className="font-mono" style={{ color: '#8b949e' }}>{noHost.join(', ')}</span>
                </div>
              )}
            </div>
          )}
        </>
      )}

      <DetailDrawer
        open={!!selectedRow}
        title={selectedRow ? t('campaign.detail.title', { name: selectedRow.name }) : ''}
        onClose={() => selectScenario(null)}
        footer={
          selectedRow ? (
            <Link
              to={`/drill?scenario_id=${encodeURIComponent(selectedRow.scenario_id)}`}
              className="btn-secondary py-1.5 px-3 text-xs inline-flex items-center gap-1"
            >
              <Crosshair size={12} aria-hidden />
              {t('drill.proveScenario')}
            </Link>
          ) : undefined
        }
      >
        {selectedRow && (
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('campaign.col.tactic')}</div>
                <div className="mt-0.5" style={{ color: 'var(--fg)' }}>{selectedRow.tactic}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('campaign.detail.technique')}</div>
                <div className="mt-0.5 font-mono" style={{ color: 'var(--fg)' }}>{selectedRow.technique}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('campaign.detail.osFamily')}</div>
                <div className="mt-0.5" style={{ color: 'var(--fg)' }}>{selectedRow.os_family}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('campaign.detail.host')}</div>
                <div className="mt-0.5 font-mono" style={{ color: 'var(--fg)' }}>{selectedRow.host ?? '—'}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('campaign.detail.status')}</div>
                <div className="mt-0.5" style={{ color: STATUS_COLOR[selectedRow.status] }}>{t(`campaign.status.${selectedRow.status}`)}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('campaign.detail.proximity')}</div>
                <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>{selectedRow.proximity.toFixed(2)}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('campaign.detail.steps')}</div>
                <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>{selectedRow.matched_steps}/{selectedRow.total_steps}</div>
              </div>
            </div>

            {selectedRow.feed_summary && (
              <div>
                <div className="uppercase tracking-wide mb-2" style={{ color: 'var(--muted)' }}>{t('campaign.detail.feed')}</div>
                <dl className="grid grid-cols-3 gap-2">
                  <div>
                    <dt style={{ color: 'var(--muted)' }}>{t('campaign.detail.feedTotal')}</dt>
                    <dd className="tabular-nums" style={{ color: 'var(--fg)' }}>{selectedRow.feed_summary.total_events}</dd>
                  </div>
                  <div>
                    <dt style={{ color: 'var(--muted)' }}>{t('campaign.detail.feedBaseline')}</dt>
                    <dd className="tabular-nums" style={{ color: 'var(--fg)' }}>{selectedRow.feed_summary.baseline_events}</dd>
                  </div>
                  <div>
                    <dt style={{ color: 'var(--muted)' }}>{t('campaign.detail.feedInjected')}</dt>
                    <dd className="tabular-nums" style={{ color: 'var(--fg)' }}>{selectedRow.feed_summary.injected_events}</dd>
                  </div>
                </dl>
              </div>
            )}

            {selectedRow.note && (
              <div>
                <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>{t('campaign.detail.note')}</div>
                <p style={{ color: 'var(--fg)' }}>{selectedRow.note}</p>
              </div>
            )}
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
