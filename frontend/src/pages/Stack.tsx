import { useEffect, useMemo, useState } from 'react';
import { Layers, AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { apiGet, ApiError } from '../lib/api';
import Dropdown from '../components/Dropdown';
import DetailDrawer from '../components/DetailDrawer';
import ExportCsvButton from '../components/ExportCsvButton';
import { toCsv, downloadCsv, dateStamp, type CsvColumn } from '../lib/csv';
import { CritChip, toCrit } from '../lib/criticality';

/* ──────────────────────────── Types ─────────────────────────────────────── */
interface HostRow { hostname: string; zone: string; criticality: string; count: number }
interface SampleRow { host: string; timestamp: string; command: string }
interface RarityRow {
  value: string;
  occurrences: number;
  host_count: number;
  single_host: boolean;
  unique: boolean;
  first_seen: string;
  last_seen: string;
  hosts: HostRow[];
  samples: SampleRow[];
  hosts_truncated: boolean;
  samples_truncated: boolean;
}
interface RaritySummary {
  total_values: number;
  rare_values: number;
  returned: number;
  truncated: boolean;
  honesty_note: string;
}
interface RarityResult {
  dimension: string;
  params: { max_count: number; limit: number };
  summary: RaritySummary;
  rows: RarityRow[];
}

const DIMENSIONS = ['process', 'parent_child', 'host_binary'] as const;
type Dimension = (typeof DIMENSIONS)[number];

function isDimension(s: string | null): s is Dimension {
  return s != null && (DIMENSIONS as readonly string[]).includes(s);
}

function timeOnly(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/* ──────────────────────────── Page ──────────────────────────────────────── */
export default function Stack() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const dimension: Dimension = isDimension(searchParams.get('dimension'))
    ? (searchParams.get('dimension') as Dimension)
    : 'process';

  const [data, setData] = useState<RarityResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drawerRow, setDrawerRow] = useState<RarityRow | null>(null);

  const setDimension = (d: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (d === 'process') next.delete('dimension');
      else next.set('dimension', d);
      return next;
    });
  };

  useEffect(() => {
    setLoading(true);
    setError(null);
    apiGet<RarityResult>(`/api/rarity?dimension=${dimension}&max_count=5&limit=100`)
      .then((d) => { setData(d); setLoading(false); })
      .catch((e: unknown) => {
        setError(e instanceof ApiError ? e.message : t('stack.failed'));
        setLoading(false);
      });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dimension]);

  const dimOptions = useMemo(
    () => DIMENSIONS.map((d) => ({ value: d, label: t(`stack.dim.${d}`) })),
    [t],
  );

  const EXPORT_COLUMNS: CsvColumn<RarityRow>[] = [
    { header: 'value', value: (r) => r.value },
    { header: 'occurrences', value: (r) => r.occurrences },
    { header: 'host_count', value: (r) => r.host_count },
    { header: 'single_host', value: (r) => String(r.single_host) },
    { header: 'unique', value: (r) => String(r.unique) },
    { header: 'first_seen', value: (r) => r.first_seen },
    { header: 'last_seen', value: (r) => r.last_seen },
    { header: 'hosts', value: (r) => r.hosts.map((h) => h.hostname).join(' ') },
  ];

  const onExport = () => {
    if (!data || data.rows.length === 0) return;
    downloadCsv(`augur-stack-${dimension}-${dateStamp()}.csv`, toCsv(data.rows, EXPORT_COLUMNS));
  };

  return (
    <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Layers size={18} aria-hidden /> {t('stack.title')}
          </h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{t('stack.subtitle')}</p>
        </div>
        {data && data.rows.length > 0 && <ExportCsvButton onExport={onExport} label={t('stack.export')} />}
      </div>

      {/* Dimension selector */}
      <div className="max-w-xs">
        <Dropdown
          value={dimension}
          onChange={setDimension}
          options={dimOptions}
          label={t('stack.dimension')}
          aria-label={t('stack.dimension')}
        />
      </div>

      {/* Persistent honesty panel */}
      <p className="rounded-xl border p-3 text-xs italic flex items-start gap-2"
         style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--muted)' }}>
        <AlertTriangle size={14} aria-hidden style={{ flexShrink: 0, marginTop: 1 }} />
        {t('stack.honesty')}
      </p>

      {error && (
        <div className="rounded-xl border p-3 flex items-center gap-2 text-sm" role="alert"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}>
          <AlertTriangle size={14} aria-hidden /> {error}
        </div>
      )}

      {loading && <p className="text-xs" style={{ color: 'var(--muted)' }}>…</p>}

      {data && !loading && (
        <div className="space-y-3">
          <div className="text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
            {t('stack.summary', { returned: data.summary.returned, rare: data.summary.rare_values,
                                  total: data.summary.total_values })}
            {data.summary.truncated && (
              <span className="ml-2 italic">{t('stack.truncated', { rare: data.summary.rare_values })}</span>
            )}
          </div>

          {data.rows.length === 0 ? (
            <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{t('stack.empty')}</p>
          ) : (
            <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
              <table className="w-full min-w-[720px] text-xs">
                <thead style={{ background: 'var(--panel)' }}>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.cols.value')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.cols.occurrences')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.cols.hostCount')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.cols.flags')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.cols.hosts')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.cols.firstSeen')}</th>
                    <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.cols.lastSeen')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.rows.map((r) => (
                    <tr key={r.value}
                        role="button"
                        tabIndex={0}
                        aria-label={t('stack.cols.inspectRow', { value: r.value })}
                        onClick={() => setDrawerRow(r)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            if (e.key === ' ') e.preventDefault();
                            setDrawerRow(r);
                          }
                        }}
                        className="cursor-pointer hover:bg-panel focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                        style={{ borderBottom: '1px solid var(--border)' }}>
                      <td className="px-3 py-1.5 font-mono" style={{ color: 'var(--fg)' }}>{r.value}</td>
                      <td className="px-3 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{r.occurrences}</td>
                      <td className="px-3 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{r.host_count}</td>
                      <td className="px-3 py-1.5">
                        <span className="flex flex-wrap gap-1">
                          {r.single_host && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase"
                                  style={{ background: '#7a4a00', color: '#ffd28a' }}>{t('stack.flag.single')}</span>
                          )}
                          {r.unique && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase"
                                  style={{ background: '#71221c', color: '#ffb4ab' }}>{t('stack.flag.unique')}</span>
                          )}
                        </span>
                      </td>
                      <td className="px-3 py-1.5">
                        <span className="flex flex-wrap items-center gap-1">
                          {r.hosts.slice(0, 4).map((h) => (
                            <span key={h.hostname} className="flex items-center gap-1">
                              <span className="font-mono" style={{ color: 'var(--fg)' }}>{h.hostname}</span>
                              <CritChip level={toCrit(h.criticality)} />
                            </span>
                          ))}
                          {r.host_count > Math.min(4, r.hosts.length) && (
                            <span className="px-1.5 py-0.5 rounded-full text-[10px] tabular-nums italic"
                                  style={{ color: 'var(--muted)', background: 'var(--panel)' }}>
                              {t('stack.cols.moreHosts', { n: r.host_count - Math.min(4, r.hosts.length) })}
                            </span>
                          )}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{timeOnly(r.first_seen)}</td>
                      <td className="px-3 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{timeOnly(r.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Row drill */}
      <DetailDrawer open={drawerRow != null} title={drawerRow?.value ?? ''} onClose={() => setDrawerRow(null)} wide>
        {drawerRow && (
          <div className="space-y-4">
            <div>
              <h3 className="text-xs font-semibold mb-1.5" style={{ color: 'var(--fg)' }}>{t('stack.drawer.hosts')}</h3>
              <div className="rounded-lg border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
                <table className="w-full text-xs">
                  <thead style={{ background: 'var(--panel)' }}>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      <th className="px-2 py-1.5 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.drawer.host')}</th>
                      <th className="px-2 py-1.5 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.drawer.criticality')}</th>
                      <th className="px-2 py-1.5 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('stack.drawer.count')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {drawerRow.hosts.map((h) => (
                      <tr key={h.hostname} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td className="px-2 py-1.5 font-mono" style={{ color: 'var(--fg)' }}>{h.hostname}</td>
                        <td className="px-2 py-1.5"><CritChip level={toCrit(h.criticality)} /></td>
                        <td className="px-2 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{h.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {drawerRow.hosts_truncated && (
                <p className="text-[11px] italic mt-1" style={{ color: 'var(--muted)' }}>
                  {t('stack.drawer.hostsTruncated', { shown: drawerRow.hosts.length, total: drawerRow.host_count })}
                </p>
              )}
            </div>
            <div>
              <h3 className="text-xs font-semibold mb-1.5" style={{ color: 'var(--fg)' }}>{t('stack.drawer.samples')}</h3>
              <div className="space-y-1.5">
                {drawerRow.samples.map((s, i) => (
                  <div key={`${s.host}-${s.timestamp}-${i}`} className="rounded-lg border p-2"
                       style={{ borderColor: 'var(--border)' }}>
                    <div className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--muted)' }}>
                      <span className="font-mono" style={{ color: 'var(--fg)' }}>{s.host}</span>
                      <span className="tabular-nums">{timeOnly(s.timestamp)}</span>
                    </div>
                    <div className="font-mono text-[11px] mt-1 break-all" style={{ color: 'var(--muted)' }}>{s.command}</div>
                  </div>
                ))}
              </div>
              {drawerRow.samples_truncated && (
                <p className="text-[11px] italic mt-1" style={{ color: 'var(--muted)' }}>
                  {t('stack.drawer.samplesTruncated', { shown: drawerRow.samples.length })}
                </p>
              )}
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
