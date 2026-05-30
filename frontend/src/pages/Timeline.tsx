import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, ApiError } from '../lib/api';
import ExportCsvButton from '../components/ExportCsvButton';
import { toCsv, downloadCsv, dateStamp, type CsvColumn } from '../lib/csv';

interface TimelineRow {
  timestamp: string;
  host: string;
  kind: 'matched_step' | 'context';
  event_kind: string;
  label: string;
  step_id: number | null;
  step_name: string | null;
  element_id: string | null;
}
interface TimelineResponse {
  scenario_id: string;
  name: string;
  severity: string;
  hosts: string[];
  band: { from: string; to: string; pad_seconds: number };
  rows: TimelineRow[];
  matched_count: number;
  context_shown: number;
  context_total: number;
  context_truncated: boolean;
  honesty_note: string;
}

const EXPORT_COLUMNS: CsvColumn<TimelineRow>[] = [
  { header: 'timestamp', value: (r) => r.timestamp },
  { header: 'host', value: (r) => r.host },
  { header: 'kind', value: (r) => r.kind },
  { header: 'event_kind', value: (r) => r.event_kind },
  { header: 'label', value: (r) => r.label },
  { header: 'step_id', value: (r) => (r.step_id === null ? '' : String(r.step_id)) },
  { header: 'step_name', value: (r) => r.step_name ?? '' },
];

/** Render the HH:MM:SS slice of an ISO timestamp, falling back to the raw value. */
function clock(iso: string): string {
  const m = /T(\d{2}:\d{2}:\d{2})/.exec(iso);
  return m ? m[1] : iso;
}

export default function Timeline() {
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const scenarioId = searchParams.get('scenario_id')?.trim() ?? '';
  const host = searchParams.get('host')?.trim() ?? '';

  const [data, setData] = useState<TimelineResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setData(null);
    const params = new URLSearchParams({ scenario_id: scenarioId });
    if (host) params.set('host', host);
    apiGet<TimelineResponse>(`/api/timeline?${params.toString()}`)
      .then((d) => { setData(d); setLoading(false); })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : t('timeline.failedLoad'));
        setLoading(false);
      });
  }, [scenarioId, host, t]);

  const onExport = () => {
    if (!data) return;
    downloadCsv(`augur-timeline-${dateStamp()}.csv`, toCsv(data.rows, EXPORT_COLUMNS));
  };

  return (
    <div className="w-full max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            {data ? data.name : t('timeline.title')}
          </h1>
          {data ? (
            <p className="text-xs mt-0.5 flex items-center gap-2 flex-wrap" style={{ color: 'var(--muted)' }}>
              <span className="px-2 py-0.5 rounded-full text-xs font-bold uppercase"
                    style={{ background: '#71221c', color: '#ffb4ab' }}>{data.severity}</span>
              <span className="font-mono">{data.hosts.join(', ')}</span>
              <span>· {t('timeline.band')}: {clock(data.band.from)} → {clock(data.band.to)}</span>
            </p>
          ) : (
            <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{t('timeline.subtitle')}</p>
          )}
        </div>
        {data && data.rows.length > 0 && <ExportCsvButton onExport={onExport} label={t('timeline.export')} />}
      </div>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div className="w-6 h-6 rounded-full border-2 animate-spin"
               style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }} aria-label={t('timeline.loading')} />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>{t('timeline.loading')}</span>
        </div>
      )}
      {error && (
        <div className="rounded-xl border p-4 flex items-center gap-3"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }} role="alert">
          <AlertTriangle size={16} aria-hidden /> {error}
        </div>
      )}
      {data && !error && data.rows.length === 0 && (
        <div className="text-center py-16"><p className="text-sm" style={{ color: 'var(--muted)' }}>{t('timeline.empty')}</p></div>
      )}

      {data && !error && data.context_truncated && (
        <div className="text-xs rounded-lg border px-3 py-2"
             style={{ borderColor: 'var(--border)', color: 'var(--muted)', background: 'var(--panel)' }}>
          {t('timeline.truncated', { shown: data.context_shown, total: data.context_total })}
        </div>
      )}

      {data && !error && data.rows.length > 0 && (
        <ol className="space-y-0">
          {data.rows.map((r, i) => {
            const matched = r.kind === 'matched_step';
            const tone = matched ? 'var(--fg)' : 'var(--muted)';
            const dot = matched ? 'var(--accent)' : '#8b949e';
            return (
              <li key={`${r.timestamp}-${i}`} className="flex gap-3 pl-1">
                <div className="flex flex-col items-center" style={{ width: 14 }} aria-hidden>
                  <span className="rounded-full shrink-0"
                        style={{ width: matched ? 10 : 7, height: matched ? 10 : 7, background: dot, marginTop: 5 }} />
                  {i < data.rows.length - 1 && (
                    <span className="flex-1" style={{ width: 0, borderLeft: '1px solid var(--border)', minHeight: 18 }} />
                  )}
                </div>
                <div className="flex items-baseline gap-3 flex-wrap pb-3" style={{ color: tone }}>
                  <span className="text-xs tabular-nums font-mono shrink-0" style={{ color: 'var(--muted)' }}>
                    {clock(r.timestamp)}
                  </span>
                  <span className="text-xs font-mono shrink-0" style={{ color: 'var(--muted)' }}>{r.host}</span>
                  <span className={`text-xs ${matched ? 'font-semibold' : ''}`}>
                    {matched
                      ? `${t('timeline.matchedStep')} ${r.step_id} · ${r.step_name ?? ''}`
                      : r.label}
                  </span>
                  {!matched && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wide"
                          style={{ background: 'var(--border)', color: 'var(--muted)' }}>{r.event_kind}</span>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}

      {data && !error && (
        <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{data.honesty_note}</p>
      )}
    </div>
  );
}
