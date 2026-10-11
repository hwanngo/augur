import { useEffect, useState, useCallback } from 'react';
import { AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useToast } from '../store/toast';
import { useNavigate } from 'react-router-dom';
import { apiGet } from '../lib/api';
import useAuthStore from '../store/auth';
import SearchInput from '../components/SearchInput';
import Pagination from '../components/Pagination';
import TimeRangePicker, { type TimeRange } from '../components/TimeRangePicker';
import ExportCsvButton from '../components/ExportCsvButton';
import SavedFilters from '../components/SavedFilters';
import Dropdown from '../components/Dropdown';
import DetectionCard, { type Detection, type Momentum } from '../components/DetectionCard';
import { usePagination } from '../lib/usePagination';
import { toCsv, downloadCsv, downloadJson, dateStamp, type CsvColumn } from '../lib/csv';

export type { Detection };

const PAGE_SIZE = 8;

/** Serialisable saved-filter snapshot for the Dashboard. */
export interface DashboardFilter {
  severity: string;
  zone: string;
  minProximity: number;
  range: TimeRange;
}

/* ──────────────────────────── CSV columns ───────────────────────────────── */
const DETECTION_CSV_COLUMNS: CsvColumn<Detection>[] = [
  { header: 'scenario_id', value: (d) => d.scenario_id },
  { header: 'name', value: (d) => d.name },
  { header: 'severity', value: (d) => d.severity },
  { header: 'proximity', value: (d) => d.proximity },
  { header: 'matched_steps', value: (d) => d.matched_steps.length },
  { header: 'total_steps', value: (d) => d.matched_steps.length + d.missing_steps.length },
  { header: 'affected_hosts', value: (d) => d.affected_hosts.join('; ') },
  { header: 'affected_zones', value: (d) => d.affected_zones.join('; ') },
];

/* ──────────────────────────── Dashboard page ────────────────────────────── */
export default function Dashboard() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const [all, setAll] = useState<Detection[]>([]);
  const [momentum, setMomentum] = useState<Map<string, Momentum>>(new Map());
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [minProximity, setMinProximity] = useState(0.3);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [zone, setZone] = useState('');
  const [range, setRange] = useState<TimeRange>({ preset: 'all', from: null, to: null });
  const showToast = useToast();
  const [realData, setRealData] = useState(false);

  const applySavedFilter = useCallback((f: DashboardFilter) => {
    setSeverity(f.severity);
    setZone(f.zone);
    setMinProximity(f.minProximity);
    setRange(f.range);
  }, []);

  const openCase = useCallback(
    (d: Detection) => {
      navigate(`/timeline?scenario_id=${encodeURIComponent(d.scenario_id)}`);
    },
    [navigate]
  );

  const openPivot = useCallback(
    (d: Detection) => {
      navigate(`/pivot?detection=${encodeURIComponent(d.scenario_id)}`);
    },
    [navigate]
  );

  // Fetch on mount + whenever the time range changes (windowing re-runs the engine server-side).
  useEffect(() => {
    const params = new URLSearchParams({ min_proximity: '0' });
    if (range.from) params.set('from', range.from);
    if (range.to) params.set('to', range.to);
    setLoading(true);
    apiGet<Detection[]>(`/api/detections?${params.toString()}`)
      .then((data) => {
        setAll(data);
        setLoading(false);
      })
      .catch((err: unknown) => {
        setFetchError(err instanceof Error ? err.message : 'Failed to load detections');
        setLoading(false);
      });
  }, [range.from, range.to]);

  // One /api/momentum fetch per range (mirrors the detections effect); join by scenario_id.
  useEffect(() => {
    const params = new URLSearchParams({ min_proximity: '0' });
    if (range.from) params.set('from', range.from);
    if (range.to) params.set('to', range.to);
    apiGet<{ series: (Momentum & { scenario_id: string })[] }>(`/api/momentum?${params.toString()}`)
      .then((data) => setMomentum(new Map(data.series.map((s) => [s.scenario_id, s]))))
      .catch(() => setMomentum(new Map()));   // momentum is progressive enhancement; never blocks cards
  }, [range.from, range.to]);

  // Read-only "real dataset" flag from the liveness probe (default false ⇒ no banner).
  useEffect(() => {
    apiGet<{ real_data?: boolean }>('/api/health')
      .then((h) => setRealData(Boolean(h.real_data)))
      .catch(() => setRealData(false));   // health is best-effort; never blocks the page
  }, []);

  // Zone option union computed client-side from the loaded detections.
  const zoneOptions = Array.from(
    new Set(all.flatMap((d) => d.affected_zones))
  ).sort();

  // Client-side filter: severity + zone + proximity slider + free-text search
  const q = query.trim().toLowerCase();
  const filtered = all.filter((d) => {
    if (d.proximity < minProximity) return false;
    if (severity && d.severity !== severity) return false;
    if (zone && !d.affected_zones.includes(zone)) return false;
    if (!q) return true;
    return (
      d.name.toLowerCase().includes(q) ||
      d.scenario_id.toLowerCase().includes(q) ||
      d.affected_hosts.some((h) => h.toLowerCase().includes(q))
    );
  });

  const { page, setPage, pageCount, pageItems, total, start, end } = usePagination(filtered, PAGE_SIZE);

  const handleSlider = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setMinProximity(Number(e.target.value));
  }, []);

  const handleExport = useCallback(() => {
    downloadCsv(`augur-detections-${dateStamp()}.csv`, toCsv(filtered, DETECTION_CSV_COLUMNS));
  }, [filtered]);

  const handleExportLayer = useCallback(() => {
    const params = new URLSearchParams({
      type: 'detections',
      min_proximity: String(minProximity),  // [AUDIT #4] slider state, NOT the fetch param (0)
    });
    if (range.from) params.set('from', range.from);
    if (range.to) params.set('to', range.to);
    apiGet<unknown>(`/api/navigator_layer?${params.toString()}`)
      .then((layer) => downloadJson(`augur-attack-detections-${dateStamp()}.json`, layer))
      .catch((err: unknown) => showToast(err instanceof Error ? err.message : 'Export failed', 'error'));
  }, [minProximity, range.from, range.to, showToast]);

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {realData && (
        <div
          role="status"
          className="flex items-center gap-2 rounded-md px-3 py-2 text-xs font-medium"
          style={{ background: 'var(--warn-bg, #3a2a00)', color: 'var(--warn-fg, #ffcc66)' }}
        >
          <AlertTriangle size={14} />
          {t('dashboard.realDatasetBanner')}
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            {t('dashboard.title')}
          </h1>
          {!loading && !fetchError && (
            <p className="text-xs mt-0.5 tabular-nums" style={{ color: 'var(--muted)' }}>
              {t('dashboard.detectionCount', {
                count: filtered.length,
                proximity: minProximity.toFixed(2),
              })}
            </p>
          )}
        </div>

        {/* Time range + filters + search + slider */}
        <div className="flex items-center gap-3 flex-wrap">
        <TimeRangePicker value={range} onChange={setRange} label={t('common.timeRange.label')} />
        {!loading && !fetchError && (
          <>
          <Dropdown
            value={severity}
            onChange={setSeverity}
            aria-label={t('dashboard.filters.severity')}
            options={[
              { value: '', label: t('dashboard.filters.allSeverities') },
              ...(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => ({ value: s, label: s })),
            ]}
          />
          <Dropdown
            value={zone}
            onChange={setZone}
            aria-label={t('dashboard.filters.zone')}
            options={[
              { value: '', label: t('dashboard.filters.allZones') },
              ...zoneOptions.map((z) => ({ value: z, label: z })),
            ]}
          />
          </>
        )}
        {!loading && !fetchError && (
          <SearchInput value={query} onChange={setQuery} label={t('common.search')} placeholder={t('dashboard.search')} />
        )}
        <label className="flex items-center gap-3 shrink-0" htmlFor="min-proximity">
          <span className="text-xs" style={{ color: 'var(--muted)' }}>
            {t('dashboard.minProximity')}
          </span>
          <input
            id="min-proximity"
            type="range"
            min={0}
            max={1}
            step={0.05}
            value={minProximity}
            onChange={handleSlider}
            className="w-36"
            aria-label={`${t('dashboard.minProximity')}: ${minProximity.toFixed(2)}`}
          />
          <span className="text-sm font-bold tabular-nums w-10" style={{ color: 'var(--fg)' }}>
            {minProximity.toFixed(2)}
          </span>
        </label>
        {!loading && !fetchError && (
          <SavedFilters<DashboardFilter>
            scope="dashboard"
            user={user}
            current={{ severity, zone, minProximity, range }}
            onApply={applySavedFilter}
            show={showToast}
          />
        )}
        {!loading && !fetchError && (
          <ExportCsvButton onExport={handleExport} disabled={filtered.length === 0} label={t('common.exportCsv')} />
        )}
        {!loading && !fetchError && (
          <ExportCsvButton onExport={handleExportLayer} disabled={false} label={t('common.exportAttackLayer')} />
        )}
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 border-t-(--accent) animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('dashboard.loading')}
          />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('dashboard.loading')}
          </span>
        </div>
      )}

      {/* Error */}
      {fetchError && (
        <div
          className="rounded-xl border p-4 flex items-center gap-3"
          style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}
          role="alert"
        >
          <AlertTriangle size={16} aria-hidden />
          <span className="text-sm">{fetchError}</span>
        </div>
      )}

      {/* Empty */}
      {!loading && !fetchError && filtered.length === 0 && (
        <div className="text-center py-16">
          <p className="text-sm" style={{ color: 'var(--muted)' }}>
            {q ? t('common.noMatches') : t('dashboard.emptyState')}
          </p>
        </div>
      )}

      {/* Cards */}
      <div className="space-y-4">
        {pageItems.map((d) => (
          <DetectionCard key={d.scenario_id} d={{ ...d, momentum: momentum.get(d.scenario_id) }} onOpenCase={openCase} onPivot={openPivot} showPlaybook />
        ))}
      </div>

      {!loading && !fetchError && (
        <Pagination page={page} pageCount={pageCount} total={total} start={start} end={end} onPage={setPage} />
      )}

    </div>
  );
}
