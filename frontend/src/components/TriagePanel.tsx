import { useEffect, useState } from 'react';
import { AlertTriangle, UserPlus, CheckCircle2, RotateCcw, Plus } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, ApiError } from '../lib/api';
import ExportCsvButton from './ExportCsvButton';
import TimeRangePicker, { type TimeRange } from './TimeRangePicker';
import { toCsv, downloadCsv, dateStamp, type CsvColumn } from '../lib/csv';

interface TriageDelta {
  alert_id: string; scenario_id: string; scenario_name: string; severity: string;
  assignee: string; status: string; ts: string; ts_field: string;
}
interface TriageResponse {
  window: { from: string | null; to: string | null };
  meta: { basis: string; deterministic: boolean };
  triage: { new_alerts: TriageDelta[]; assigned: TriageDelta[]; resolved: TriageDelta[]; reopened: TriageDelta[] };
  summary: { counts: Record<string, number> };
}

const EXPORT_COLUMNS: CsvColumn<TriageDelta & { section: string }>[] = [
  { header: 'section', value: (r) => r.section },
  { header: 'alert_id', value: (r) => r.alert_id },
  { header: 'scenario_id', value: (r) => r.scenario_id },
  { header: 'scenario_name', value: (r) => r.scenario_name },
  { header: 'severity', value: (r) => r.severity },
  { header: 'assignee', value: (r) => r.assignee },
  { header: 'status', value: (r) => r.status },
  { header: 'when', value: (r) => r.ts },
];

export default function TriagePanel() {
  const { t } = useTranslation();
  const [data, setData] = useState<TriageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [range, setRange] = useState<TimeRange>({ preset: 'all', from: null, to: null });

  useEffect(() => {
    const qs = range.from && range.to
      ? `?from=${encodeURIComponent(range.from)}&to=${encodeURIComponent(range.to)}`
      : '';
    setLoading(true);
    apiGet<TriageResponse>(`/api/triage_handover${qs}`)
      // tolerate a malformed/triage-less response (the real backend always returns `triage`)
      .then((d) => { setData(d?.triage ? d : null); setLoading(false); })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : t('handover.triage.failedLoad'));
        setLoading(false);
      });
  }, [t, range.from, range.to]);

  const onExport = () => {
    if (!data) return;
    const rows: (TriageDelta & { section: string })[] = [];
    (['new_alerts', 'assigned', 'resolved', 'reopened'] as const).forEach((k) =>
      data.triage[k].forEach((r) => rows.push({ ...r, section: k })));
    downloadCsv(`augur-triage-handover-${dateStamp()}.csv`, toCsv(rows, EXPORT_COLUMNS));
  };

  const sections: { key: keyof TriageResponse['triage']; labelKey: string; tone: string; Icon: typeof Plus }[] = [
    { key: 'new_alerts', labelKey: 'handover.triage.sections.newAlerts', tone: '#7ee787', Icon: Plus },
    { key: 'assigned', labelKey: 'handover.triage.sections.assigned', tone: '#9fc7ef', Icon: UserPlus },
    { key: 'resolved', labelKey: 'handover.triage.sections.resolved', tone: '#7ee787', Icon: CheckCircle2 },
    { key: 'reopened', labelKey: 'handover.triage.sections.reopened', tone: '#ffd28a', Icon: RotateCcw },
  ];
  const total = data ? sections.reduce((n, s) => n + data.triage[s.key].length, 0) : 0;

  return (
    <div className="rounded-xl border" style={{ borderColor: 'var(--border)' }}>
      <div className="px-3 py-2 flex items-center justify-between flex-wrap gap-2" style={{ background: 'var(--panel)' }}>
        <div>
          <div className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>{t('handover.triage.title')}</div>
          <div className="text-xs" style={{ color: 'var(--muted)' }}>{t('handover.triage.clockNote')}</div>
        </div>
        <div className="flex items-center gap-2">
          <TimeRangePicker value={range} onChange={setRange} label={t('handover.triage.title')} />
          {data && <ExportCsvButton onExport={onExport} label={t('handover.triage.export')} />}
        </div>
      </div>

      {loading && (
        <div className="px-3 py-6 text-sm" style={{ color: 'var(--muted)' }}>{t('handover.triage.loading')}</div>
      )}
      {error && (
        <div className="px-3 py-4 flex items-center gap-2 text-sm" style={{ color: '#ffb4ab' }} role="alert">
          <AlertTriangle size={16} aria-hidden /> {error}
        </div>
      )}

      {data && !error && data.window.from === null && (
        <div className="px-3 py-6 text-sm" style={{ color: 'var(--muted)' }}>{t('handover.triage.emptyNoData')}</div>
      )}
      {data && !error && data.window.from !== null && total === 0 && (
        <div className="px-3 py-6 text-sm" style={{ color: 'var(--muted)' }}>{t('handover.triage.emptyWindow')}</div>
      )}

      {data && !error && total > 0 && (
        <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
          {sections.filter((s) => data.triage[s.key].length > 0).map((s) => (
            <div key={s.key}>
              <div className="px-3 py-1.5 text-xs font-semibold flex items-center gap-2" style={{ color: s.tone }}>
                <s.Icon size={13} aria-hidden /> {t(s.labelKey)} <span className="opacity-60">({data.triage[s.key].length})</span>
              </div>
              <table className="w-full text-sm">
                <tbody>
                  {data.triage[s.key].map((r) => (
                    <tr key={`${s.key}-${r.alert_id}-${r.ts}`} style={{ borderTop: '1px solid var(--border)' }}>
                      <td className="px-3 py-1.5 font-mono text-xs" style={{ color: 'var(--fg)' }}>{r.scenario_id}</td>
                      <td className="px-3 py-1.5 text-xs" style={{ color: 'var(--muted)' }}>{r.scenario_name}</td>
                      <td className="px-3 py-1.5 text-xs" style={{ color: 'var(--muted)' }}>{r.severity}</td>
                      <td className="px-3 py-1.5 text-xs" style={{ color: 'var(--muted)' }}>{r.assignee || '—'}</td>
                      <td className="px-3 py-1.5 text-xs" style={{ color: 'var(--muted)' }}>{r.status}</td>
                      <td className="px-3 py-1.5 text-xs tabular-nums text-right" style={{ color: 'var(--muted)' }}>{r.ts}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
