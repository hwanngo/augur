import { useEffect, useState } from 'react';
import { ChevronUp, ChevronDown, Minus, AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { apiGet, ApiError } from '../lib/api';
import SearchInput from '../components/SearchInput';
import Pagination from '../components/Pagination';
import DetailDrawer from '../components/DetailDrawer';
import { usePagination } from '../lib/usePagination';
import { CritChip, type Crit } from '../lib/criticality';

const PAGE_SIZE = 12;

/* ──────────────────────────── Types ─────────────────────────────────────── */
type Band = 'CRITICAL' | 'HIGH' | 'WATCH' | 'LOW' | 'CLEAR';

export interface TopScenario {
  scenario_id: string;
  name: string;
  severity: string;
  proximity: number;
}

export interface HostRow {
  hostname: string;
  zone: string;
  criticality: Crit;
  score: number;
  band: Band;
  detection_count: number;
  max_proximity: number;
  top_severity: string | null;
  top_scenarios: TopScenario[];
}

interface HostRiskResponse {
  hosts: HostRow[];
}

/* ──────────────────────────── Band chip ─────────────────────────────────── */
const BAND_STYLE: Record<Band, { bg: string; fg: string }> = {
  CRITICAL: { bg: '#71221c', fg: '#ffb4ab' },
  HIGH:     { bg: '#7a4a00', fg: '#ffd28a' },
  WATCH:    { bg: '#39402a', fg: '#d8e08a' },
  LOW:      { bg: '#23364a', fg: '#9fc7ef' },
  CLEAR:    { bg: '#21262d', fg: '#8b949e' },
};

function BandChip({ band }: { band: Band }) {
  const { t } = useTranslation();
  const { bg, fg } = BAND_STYLE[band];
  return (
    <span
      className="px-2 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide"
      style={{ background: bg, color: fg }}
    >
      {t(`hostRisk.bands.${band}`)}
    </span>
  );
}

/* ──────────────────────────── Sorting ───────────────────────────────────── */
type SortKey = 'hostname' | 'zone' | 'criticality' | 'score' | 'band' | 'detection_count';
type SortDir = 'asc' | 'desc';

const CRIT_ORDER: Record<Crit, number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1,
};
const BAND_ORDER: Record<Band, number> = {
  CRITICAL: 5, HIGH: 4, WATCH: 3, LOW: 2, CLEAR: 1,
};

/* ──────────────────────────── Host Risk page ────────────────────────────── */
export default function HostRisk() {
  const { t } = useTranslation();
  const [hosts, setHosts] = useState<HostRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>('score');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [query, setQuery] = useState('');

  const [searchParams, setSearchParams] = useSearchParams();
  const selectedHost = searchParams.get('host');
  const selectHost = (hostname: string | null) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (hostname) next.set('host', hostname); else next.delete('host');
      return next;
    });
  };
  const selected = hosts.find((h) => h.hostname === selectedHost) ?? null;

  useEffect(() => {
    apiGet<HostRiskResponse>('/api/host_risk')
      .then((data) => { setHosts(data.hosts); setLoading(false); })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : t('hostRisk.failedLoad'));
        setLoading(false);
      });
  }, [t]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir(key === 'score' ? 'desc' : 'asc'); }
  };

  const q = query.trim().toLowerCase();
  const filtered = hosts.filter((h) =>
    !q ||
    h.hostname.toLowerCase().includes(q) ||
    h.zone.toLowerCase().includes(q) ||
    h.band.toLowerCase().includes(q)
  );

  const sorted = [...filtered].sort((a, b) => {
    let cmp: number;
    if (sortKey === 'criticality') cmp = CRIT_ORDER[a.criticality] - CRIT_ORDER[b.criticality];
    else if (sortKey === 'band') cmp = BAND_ORDER[a.band] - BAND_ORDER[b.band];
    else if (sortKey === 'score' || sortKey === 'detection_count') cmp = a[sortKey] - b[sortKey];
    else cmp = String(a[sortKey]) < String(b[sortKey]) ? -1 : String(a[sortKey]) > String(b[sortKey]) ? 1 : 0;
    return sortDir === 'asc' ? cmp : -cmp;
  });

  const { page, setPage, pageCount, pageItems, total, start, end } = usePagination(sorted, PAGE_SIZE);

  function SortIcon({ col }: { col: SortKey }) {
    if (sortKey !== col) return <Minus size={12} className="opacity-30" aria-hidden />;
    return sortDir === 'asc'
      ? <ChevronUp size={12} aria-hidden />
      : <ChevronDown size={12} aria-hidden />;
  }

  function Th({ col, label }: { col: SortKey; label: string }) {
    return (
      <th
        className="px-3 py-2.5 text-left text-xs font-medium cursor-pointer select-none whitespace-nowrap transition-colors hover:text-(--fg)"
        style={{ color: 'var(--muted)' }}
        onClick={() => handleSort(col)}
        aria-sort={sortKey === col ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}
      >
        <span className="flex items-center gap-1">
          {label} <SortIcon col={col} />
        </span>
      </th>
    );
  }

  return (
    <div className="w-full max-w-(--breakpoint-2xl) mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            {t('hostRisk.title')}
          </h1>
          {!loading && !error && (
            <p className="text-xs mt-0.5 tabular-nums" style={{ color: 'var(--muted)' }}>
              {t('hostRisk.hostCount', { count: hosts.length })}
            </p>
          )}
        </div>
        {!loading && !error && (
          <SearchInput value={query} onChange={setQuery} label={t('common.search')} placeholder={t('hostRisk.search')} />
        )}
      </div>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('hostRisk.loading')}
          />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('hostRisk.loading')}
          </span>
        </div>
      )}

      {error && (
        <div
          className="rounded-xl border p-4 flex items-center gap-3"
          style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}
          role="alert"
        >
          <AlertTriangle size={16} aria-hidden />
          {error}
        </div>
      )}

      {!loading && !error && hosts.length === 0 && (
        <div className="text-center py-16">
          <p className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('hostRisk.empty')}
          </p>
        </div>
      )}

      {!loading && !error && hosts.length > 0 && (
        <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
          <table className="w-full min-w-[720px] text-sm" aria-label={t('hostRisk.ariaLabel')}>
            <thead style={{ background: 'var(--panel)' }}>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <Th col="hostname" label={t('hostRisk.table.host')} />
                <Th col="zone" label={t('hostRisk.table.zone')} />
                <Th col="criticality" label={t('hostRisk.table.criticality')} />
                <Th col="score" label={t('hostRisk.table.score')} />
                <Th col="band" label={t('hostRisk.table.band')} />
                <Th col="detection_count" label={t('hostRisk.table.detections')} />
                <th className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>
                  {t('hostRisk.table.scenarios')}
                </th>
              </tr>
            </thead>
            <tbody>
              {pageItems.map((h) => (
                <tr
                  key={h.hostname}
                  className="transition-colors hover:bg-[#1e242c]"
                  style={{
                    borderBottom: '1px solid var(--border)',
                    background: selectedHost === h.hostname ? '#1b2129' : undefined,
                  }}
                >
                  <td className="px-3 py-2.5">
                    <button
                      type="button"
                      onClick={() => selectHost(h.hostname)}
                      aria-current={selectedHost === h.hostname}
                      aria-label={t('hostRisk.detail.open', { name: h.hostname })}
                      className="font-medium font-mono text-xs text-left cursor-pointer hover:underline focus:underline focus:outline-hidden"
                      style={{
                        color: 'var(--fg)',
                        boxShadow:
                          selectedHost === h.hostname ? 'inset 2px 0 0 0 var(--accent)' : undefined,
                      }}
                    >
                      {h.hostname}
                    </button>
                  </td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--muted)' }}>
                    {h.zone}
                  </td>
                  <td className="px-3 py-2.5">
                    <CritChip level={h.criticality} />
                  </td>
                  <td className="px-3 py-2.5 text-xs tabular-nums" style={{ color: 'var(--fg)' }}>
                    {h.score}
                  </td>
                  <td className="px-3 py-2.5">
                    <BandChip band={h.band} />
                  </td>
                  <td className="px-3 py-2.5 text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                    {h.detection_count}
                  </td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--muted)' }}>
                    {h.top_scenarios.length === 0 ? '—' : (
                      <>
                        {h.top_scenarios[0].name}
                        {h.top_scenarios.length > 1 && (
                          <span className="ml-1 opacity-70">
                            {t('hostRisk.moreScenarios', { count: h.top_scenarios.length - 1 })}
                          </span>
                        )}
                      </>
                    )}
                  </td>
                </tr>
              ))}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-3 py-8 text-center text-sm" style={{ color: 'var(--muted)' }}>
                    {t('common.noMatches')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {!loading && !error && hosts.length > 0 && (
        <Pagination page={page} pageCount={pageCount} total={total} start={start} end={end} onPage={setPage} />
      )}

      <DetailDrawer
        open={!!selected}
        title={selected ? t('hostRisk.detail.title', { name: selected.hostname }) : ''}
        onClose={() => selectHost(null)}
      >
        {selected && (
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('hostRisk.detail.zone')}</div>
                <div className="mt-0.5" style={{ color: 'var(--fg)' }}>{selected.zone}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('hostRisk.detail.criticality')}</div>
                <div className="mt-1"><CritChip level={selected.criticality} /></div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('hostRisk.detail.score')}</div>
                <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>{selected.score}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('hostRisk.detail.band')}</div>
                <div className="mt-1"><BandChip band={selected.band} /></div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('hostRisk.detail.detections')}</div>
                <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>{selected.detection_count}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('hostRisk.detail.maxProximity')}</div>
                <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>{selected.max_proximity}</div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('hostRisk.detail.topSeverity')}</div>
                <div className="mt-0.5" style={{ color: 'var(--fg)' }}>{selected.top_severity ?? '—'}</div>
              </div>
            </div>
            <div>
              <div className="uppercase tracking-wide mb-2" style={{ color: 'var(--muted)' }}>{t('hostRisk.detail.topScenarios')}</div>
              {selected.top_scenarios.length === 0 ? (
                <p style={{ color: 'var(--muted)' }}>{t('hostRisk.detail.noScenarios')}</p>
              ) : (
                <ul className="space-y-2">
                  {selected.top_scenarios.map((s) => (
                    <li
                      key={s.scenario_id}
                      className="rounded-lg border p-2"
                      style={{ borderColor: 'var(--border)', background: 'var(--bg)' }}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono" style={{ color: 'var(--muted)' }}>{s.scenario_id}</span>
                        <span className="tabular-nums" style={{ color: 'var(--fg)' }}>{s.proximity}</span>
                      </div>
                      <div className="mt-0.5" style={{ color: 'var(--fg)' }}>{s.name}</div>
                      <div className="mt-0.5 uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{s.severity}</div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
