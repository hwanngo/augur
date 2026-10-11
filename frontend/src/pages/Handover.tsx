import { useEffect, useState } from 'react';
import { ArrowUpRight, ArrowDownRight, Plus, X, AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, ApiError } from '../lib/api';
import ExportCsvButton from '../components/ExportCsvButton';
import TriagePanel from '../components/TriagePanel';
import { toCsv, downloadCsv, dateStamp, type CsvColumn } from '../lib/csv';

interface DetectionDelta {
  scenario_id: string; name: string; severity: string;
  proximity_prior: number | null; proximity_current: number | null; proximity_delta: number;
  band_prior: string | null; band_current: string | null; band_changed: boolean; affected_hosts: string[];
}
interface HostDelta {
  hostname: string; zone: string; criticality: string;
  score_prior: number; score_current: number; score_delta: number; band_prior: string; band_current: string;
}
interface HandoverResponse {
  window: { from: string; to: string };
  meta: { min_proximity: number; basis: string; deterministic: boolean };
  detections: { new: DetectionDelta[]; escalated: DetectionDelta[]; decayed: DetectionDelta[]; gone: DetectionDelta[]; unchanged_count: number };
  host_risk: { entered: HostDelta[]; left: HostDelta[]; escalated: HostDelta[]; deescalated: HostDelta[] };
  summary: { counts: Record<string, number> };
}

const fmt = (p: number | null) => (p === null ? '—' : p.toFixed(2));

interface ExportRow {
  section: string;
  delta: DetectionDelta;
}

const EXPORT_COLUMNS: CsvColumn<ExportRow>[] = [
  { header: 'section', value: (r) => r.section },
  { header: 'scenario_id', value: (r) => r.delta.scenario_id },
  { header: 'name', value: (r) => r.delta.name },
  { header: 'prior', value: (r) => fmt(r.delta.proximity_prior) },
  { header: 'current', value: (r) => fmt(r.delta.proximity_current) },
  { header: 'delta', value: (r) => String(r.delta.proximity_delta) },
];

export default function Handover() {
  const { t } = useTranslation();
  const [data, setData] = useState<HandoverResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<HandoverResponse>('/api/handover?min_proximity=0.30')
      .then((d) => { setData(d); setLoading(false); })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : t('handover.failedLoad'));
        setLoading(false);
      });
  }, [t]);

  const onExport = () => {
    if (!data) return;
    const rows: ExportRow[] = [];
    const push = (section: string, list: DetectionDelta[]) =>
      list.forEach((d) => rows.push({ section, delta: d }));
    push('new', data.detections.new);
    push('escalated', data.detections.escalated);
    push('decayed', data.detections.decayed);
    push('gone', data.detections.gone);
    downloadCsv(`augur-handover-${dateStamp()}.csv`, toCsv(rows, EXPORT_COLUMNS));
  };

  const c = data?.summary.counts ?? {};
  const totalChanges =
    (c.new ?? 0) + (c.escalated ?? 0) + (c.decayed ?? 0) + (c.gone ?? 0) +
    (c.hosts_entered ?? 0) + (c.hosts_left ?? 0) +
    (c.hosts_escalated ?? 0) + (c.hosts_deescalated ?? 0);

  function DetSection({ titleKey, list, tone, Icon }: { titleKey: string; list: DetectionDelta[]; tone: string; Icon: typeof Plus }) {
    if (list.length === 0) return null;
    return (
      <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
        <div className="px-3 py-2 text-xs font-semibold flex items-center gap-2" style={{ background: 'var(--panel)', color: tone }}>
          <Icon size={14} aria-hidden /> {t(titleKey)} <span className="opacity-60">({list.length})</span>
        </div>
        <table className="w-full text-sm">
          <tbody>
            {list.map((d) => (
              <tr key={d.scenario_id} style={{ borderTop: '1px solid var(--border)' }}>
                <td className="px-3 py-2 font-mono text-xs" style={{ color: 'var(--fg)' }}>{d.scenario_id}</td>
                <td className="px-3 py-2 text-xs" style={{ color: 'var(--muted)' }}>{d.name}</td>
                <td className="px-3 py-2 text-xs tabular-nums text-right" style={{ color: 'var(--muted)' }}>
                  {fmt(d.proximity_prior)} → {fmt(d.proximity_current)}
                </td>
                <td className="px-3 py-2 text-xs tabular-nums text-right" style={{ color: tone }}>
                  {d.proximity_delta > 0 ? '+' : ''}{d.proximity_delta}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div className="w-full max-w-(--breakpoint-2xl) mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{t('handover.title')}</h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{t('handover.subtitle')}</p>
        </div>
        {data && <ExportCsvButton onExport={onExport} label={t('handover.export')} />}
      </div>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div className="w-6 h-6 rounded-full border-2 animate-spin" style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }} aria-label={t('handover.loading')} />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>{t('handover.loading')}</span>
        </div>
      )}

      {error && (
        <div className="rounded-xl border p-4 flex items-center gap-3" style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }} role="alert">
          <AlertTriangle size={16} aria-hidden /> {error}
        </div>
      )}

      {data && !error && (
        <>
          <p className="text-sm tabular-nums" style={{ color: 'var(--fg)' }}>
            {t('handover.summary', { new: c.new ?? 0, escalated: c.escalated ?? 0, decayed: c.decayed ?? 0, gone: c.gone ?? 0, hostsEntered: c.hosts_entered ?? 0 })}
          </p>

          {totalChanges === 0 && (
            <div className="text-center py-12">
              <p className="text-sm" style={{ color: 'var(--muted)' }}>{t('handover.empty')}</p>
            </div>
          )}

          <div className="grid gap-4 md:grid-cols-2">
            <DetSection titleKey="handover.sections.new" list={data.detections.new} tone="#7ee787" Icon={Plus} />
            <DetSection titleKey="handover.sections.escalated" list={data.detections.escalated} tone="#ffd28a" Icon={ArrowUpRight} />
            <DetSection titleKey="handover.sections.decayed" list={data.detections.decayed} tone="#9fc7ef" Icon={ArrowDownRight} />
            <DetSection titleKey="handover.sections.gone" list={data.detections.gone} tone="#8b949e" Icon={X} />
          </div>

          {(data.host_risk.entered.length > 0 || data.host_risk.left.length > 0 ||
            data.host_risk.escalated.length > 0 || data.host_risk.deescalated.length > 0) && (
            <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
              <div className="px-3 py-2 text-xs font-semibold" style={{ background: 'var(--panel)', color: 'var(--fg)' }}>
                {t('handover.sections.hostMovement')}
              </div>
              <table className="w-full text-sm">
                <tbody>
                  {[
                    { list: data.host_risk.entered, prefix: 'in', mark: '＋', tone: '#7ee787' },
                    { list: data.host_risk.left, prefix: 'out', mark: '－', tone: '#8b949e' },
                    { list: data.host_risk.escalated, prefix: 'up', mark: '↑', tone: '#ffd28a' },
                    { list: data.host_risk.deescalated, prefix: 'down', mark: '↓', tone: '#9fc7ef' },
                  ].flatMap(({ list, prefix, mark, tone }) =>
                    list.map((h) => (
                      <tr key={`${prefix}-${h.hostname}`} style={{ borderTop: '1px solid var(--border)' }}>
                        <td className="px-3 py-2 text-xs" style={{ color: tone }}>{mark}</td>
                        <td className="px-3 py-2 font-mono text-xs" style={{ color: 'var(--fg)' }}>{h.hostname}</td>
                        <td className="px-3 py-2 text-xs tabular-nums text-right" style={{ color: 'var(--muted)' }}>{h.score_prior} → {h.score_current}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('handover.basisNote')}</p>
          <TriagePanel />
        </>
      )}
    </div>
  );
}
