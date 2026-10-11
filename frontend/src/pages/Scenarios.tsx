import { useEffect, useState } from 'react';
import { ChevronUp, ChevronDown, Minus, AlertTriangle, Crosshair } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { apiGet, ApiError } from '../lib/api';
import { downloadText, dateStamp } from '../lib/csv';
import { useToast } from '../store/toast';
import SearchInput from '../components/SearchInput';
import Dropdown from '../components/Dropdown';
import Pagination from '../components/Pagination';
import DetailDrawer from '../components/DetailDrawer';
import { usePagination } from '../lib/usePagination';

const PAGE_SIZE = 12;
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

interface MitreMapping {
  tactic: string;
  technique: string;
}

export interface Scenario {
  scenario_id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  steps: number;
  os_family: string;
  applicable_zones: string[];
  mitre: MitreMapping[];
}

interface ScenarioStep {
  step_id: number;
  name: string;
  temporal_link: { previous_step: number; min_time_delta_seconds: number; max_time_delta_seconds: number; link_scope: string } | null;
  matching_criteria: Record<string, unknown>;
}
export interface ScenarioDetail {
  scenario_id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  os_family: string;
  applicable_zones: string[];
  mitre: MitreMapping[];
  step_count: number;
  steps: ScenarioStep[];
}

export interface ScenarioSigma {
  scenario_id: string;
  rules: Array<Record<string, unknown>>;
  yaml: string;
  honesty_note: string;
}

const SEV_STYLE: Record<Scenario['severity'], { bg: string; fg: string }> = {
  CRITICAL: { bg: '#71221c', fg: '#ffb4ab' },
  HIGH:     { bg: '#7a4a00', fg: '#ffd28a' },
  MEDIUM:   { bg: '#39402a', fg: '#d8e08a' },
  LOW:      { bg: '#23364a', fg: '#9fc7ef' },
};

type SortKey = 'scenario_id' | 'name' | 'severity' | 'steps';
type SortDir = 'asc' | 'desc';

const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

export default function Scenarios() {
  const { t } = useTranslation();
  const toast = useToast();
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>('severity');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [query, setQuery] = useState('');
  const [sevFilter, setSevFilter] = useState('');

  const [searchParams, setSearchParams] = useSearchParams();
  const selectedId = searchParams.get('scenario');
  const selectScenario = (id: string | null) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (id) next.set('scenario', id); else next.delete('scenario');
      return next;
    });
  };
  const selectedMeta = scenarios.find((s) => s.scenario_id === selectedId) ?? null;
  const [detail, setDetail] = useState<ScenarioDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [sigma, setSigma] = useState<ScenarioSigma | null>(null);
  const [sigmaLoading, setSigmaLoading] = useState(false);
  const [sigmaError, setSigmaError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!selectedId) { setDetail(null); setDetailError(null); setDetailLoading(false); return; }
    let cancelled = false;
    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    apiGet<ScenarioDetail>(`/api/scenarios/${encodeURIComponent(selectedId)}`)
      .then((d) => { if (!cancelled) { setDetail(d); setDetailLoading(false); } })
      .catch((err: unknown) => {
        if (cancelled) return;
        setDetailError(err instanceof ApiError ? err.message : t('scenarios.detail.failed'));
        setDetailLoading(false);
      });
    return () => { cancelled = true; };
     
  }, [selectedId, t]);

  useEffect(() => {
    if (!selectedId) { setSigma(null); setSigmaError(null); setSigmaLoading(false); return; }
    let cancelled = false;
    setSigma(null);
    setSigmaError(null);
    setSigmaLoading(true);
    apiGet<ScenarioSigma>(`/api/scenarios/${encodeURIComponent(selectedId)}/sigma`)
      .then((s) => { if (!cancelled) { setSigma(s); setSigmaLoading(false); } })
      .catch((err: unknown) => {
        if (cancelled) return;
        setSigmaError(err instanceof ApiError ? err.message : t('scenarios.sigma.failed'));
        setSigmaLoading(false);
      });
    return () => { cancelled = true; };
     
  }, [selectedId, t]);

  const exportPack = () => {
    apiGet<{ yaml: string }>('/api/sigma_pack?format=json')
      .then((p) => downloadText('augur-sigma-pack.yml', p.yaml, 'text/yaml'))
      .catch(() => { toast(t('scenarios.sigma.packFailed'), 'error'); });
  };

  useEffect(() => {
    apiGet<Scenario[]>('/api/scenarios')
      .then((data) => { setScenarios(data); setLoading(false); })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : t('scenarios.failedLoad'));
        setLoading(false);
      });
  }, [t]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir('asc'); }
  };

  const q = query.trim().toLowerCase();
  const filtered = scenarios.filter((s) => {
    if (sevFilter && s.severity !== sevFilter) return false;
    if (!q) return true;
    return (
      s.scenario_id.toLowerCase().includes(q) ||
      s.name.toLowerCase().includes(q) ||
      s.mitre.some((m) => m.technique.toLowerCase().includes(q) || m.tactic.toLowerCase().includes(q))
    );
  });

  const sorted = [...filtered].sort((a, b) => {
    let cmp: number;
    if (sortKey === 'severity') {
      cmp = SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
    } else if (sortKey === 'steps') {
      cmp = a.steps - b.steps;
    } else {
      cmp = a[sortKey] < b[sortKey] ? -1 : a[sortKey] > b[sortKey] ? 1 : 0;
    }
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
        <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
          {t('scenarios.title')}
        </h1>
        {!loading && !error && (
          <div className="flex items-center gap-2 flex-wrap">
            <SearchInput value={query} onChange={setQuery} label={t('common.search')} placeholder={t('scenarios.search')} />
            <Dropdown
              value={sevFilter}
              onChange={setSevFilter}
              aria-label={t('scenarios.table.severity')}
              options={[
                { value: '', label: t('common.allSeverities') },
                ...SEVERITIES.map((s) => ({ value: s, label: s })),
              ]}
            />
            <button
              type="button"
              onClick={exportPack}
              className="btn-secondary py-1.5 px-3 text-xs"
            >
              {t('scenarios.exportPack')}
            </button>
          </div>
        )}
      </div>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('scenarios.loading')}
          />
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

      {!loading && !error && (
        <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
          <table className="w-full min-w-[720px] text-sm" aria-label={t('scenarios.ariaLabel')}>
            <thead style={{ background: 'var(--panel)' }}>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <Th col="scenario_id" label={t('scenarios.table.id')} />
                <Th col="name" label={t('scenarios.table.name')} />
                <Th col="severity" label={t('scenarios.table.severity')} />
                <Th col="steps" label={t('scenarios.table.steps')} />
                <th
                  className="px-3 py-2.5 text-left text-xs font-medium"
                  style={{ color: 'var(--muted)' }}
                >
                  {t('scenarios.table.mitre')}
                </th>
                <th className="px-3 py-2.5 text-right text-xs font-medium sr-only">
                  {t('drill.proveScenario')}
                </th>
              </tr>
            </thead>
            <tbody>
              {pageItems.map((s) => {
                const { bg, fg } = SEV_STYLE[s.severity];
                return (
                  <tr
                    key={s.scenario_id}
                    className="transition-colors hover:bg-[#1e242c]"
                    style={{
                      borderBottom: '1px solid var(--border)',
                      background: selectedId === s.scenario_id ? '#1b2129' : undefined,
                    }}
                  >
                    <td className="px-3 py-2.5">
                      <button
                        type="button"
                        onClick={() => selectScenario(s.scenario_id)}
                        aria-current={selectedId === s.scenario_id}
                        aria-label={t('scenarios.detail.open', { name: s.name })}
                        className="text-xs font-mono tabular-nums text-left cursor-pointer hover:underline focus:underline focus:outline-hidden"
                        style={{
                          color: 'var(--muted)',
                          boxShadow:
                            selectedId === s.scenario_id ? 'inset 2px 0 0 0 var(--accent)' : undefined,
                        }}
                      >
                        {s.scenario_id}
                      </button>
                    </td>
                    <td className="px-3 py-2.5 font-medium" style={{ color: 'var(--fg)' }}>
                      {s.name}
                    </td>
                    <td className="px-3 py-2.5">
                      <span
                        className="px-2 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide"
                        style={{ background: bg, color: fg }}
                      >
                        {s.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 tabular-nums text-xs" style={{ color: 'var(--fg)' }}>
                      {s.steps}
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {s.mitre.map((m, i) => (
                          <span
                            key={i}
                            className="px-1.5 py-0.5 rounded-sm text-[10px] font-mono border"
                            style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--muted)' }}
                            title={`${m.tactic} — ${m.technique}`}
                          >
                            {m.technique}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2.5 text-right whitespace-nowrap">
                      <Link
                        to={`/drill?scenario_id=${encodeURIComponent(s.scenario_id)}`}
                        className="inline-flex items-center gap-1 text-xs font-medium transition-colors hover:text-(--accent)"
                        style={{ color: 'var(--muted)' }}
                      >
                        <Crosshair size={12} aria-hidden />
                        {t('drill.proveScenario')}
                      </Link>
                    </td>
                  </tr>
                );
              })}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-sm" style={{ color: 'var(--muted)' }}>
                    {query || sevFilter ? t('common.noMatches') : t('scenarios.empty')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {!loading && !error && (
        <Pagination page={page} pageCount={pageCount} total={total} start={start} end={end} onPage={setPage} />
      )}

      <DetailDrawer
        open={!!selectedMeta}
        wide
        title={selectedMeta ? t('scenarios.detail.title', { name: selectedMeta.name }) : ''}
        onClose={() => selectScenario(null)}
        footer={
          selectedMeta ? (
            <Link
              to={`/drill?scenario_id=${encodeURIComponent(selectedMeta.scenario_id)}`}
              className="btn-secondary py-1.5 px-3 text-xs inline-flex items-center gap-1"
            >
              <Crosshair size={12} aria-hidden />
              {t('drill.proveScenario')}
            </Link>
          ) : undefined
        }
      >
        {selectedMeta && (
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('scenarios.detail.severity')}</div>
                <div className="mt-1">
                  <span
                    className="px-2 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide"
                    style={{ background: SEV_STYLE[selectedMeta.severity].bg, color: SEV_STYLE[selectedMeta.severity].fg }}
                  >
                    {selectedMeta.severity}
                  </span>
                </div>
              </div>
              <div>
                <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('scenarios.detail.osFamily')}</div>
                <div className="mt-0.5" style={{ color: 'var(--fg)' }}>{selectedMeta.os_family}</div>
              </div>
            </div>

            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>{t('scenarios.detail.applicableZones')}</div>
              <div className="flex flex-wrap gap-1">
                {selectedMeta.applicable_zones.map((z) => (
                  <span key={z} className="px-1.5 py-0.5 rounded-sm text-[10px] font-mono border"
                    style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--muted)' }}>{z}</span>
                ))}
              </div>
            </div>

            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>{t('scenarios.detail.mitre')}</div>
              <div className="flex flex-wrap gap-1">
                {selectedMeta.mitre.map((m, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded-sm text-[10px] font-mono border"
                    style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--muted)' }}
                    title={`${m.tactic} — ${m.technique}`}>{m.tactic} · {m.technique}</span>
                ))}
              </div>
            </div>

            <div>
              <div className="uppercase tracking-wide mb-2" style={{ color: 'var(--muted)' }}>{t('scenarios.detail.steps')}</div>
              {detailLoading && (
                <div className="flex items-center gap-2 py-3" style={{ color: 'var(--muted)' }}>
                  <span className="w-4 h-4 rounded-full border-2 animate-spin"
                    style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
                    aria-label={t('scenarios.detail.loading')} />
                  {t('scenarios.detail.loading')}
                </div>
              )}
              {detailError && (
                <p role="alert" style={{ color: '#ffb4ab' }}>{detailError}</p>
              )}
              {detail && (
                <ol className="space-y-2">
                  {detail.steps.map((st) => (
                    <li key={st.step_id} className="rounded-lg border p-2"
                      style={{ borderColor: 'var(--border)', background: 'var(--bg)' }}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold" style={{ color: 'var(--fg)' }}>
                          {t('scenarios.detail.step', { n: st.step_id })}: {st.name}
                        </span>
                      </div>
                      {st.temporal_link && (
                        <div className="mt-1" style={{ color: 'var(--muted)' }}>
                          {t('scenarios.detail.temporalLink')}: ≤{st.temporal_link.max_time_delta_seconds}s
                          ({st.temporal_link.link_scope})
                        </div>
                      )}
                      <div className="mt-1">
                        <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('scenarios.detail.criteria')}</div>
                        <pre className="mt-0.5 whitespace-pre-wrap wrap-break-word font-mono text-[10px]" style={{ color: 'var(--fg)' }}>
                          {JSON.stringify(st.matching_criteria, null, 2)}
                        </pre>
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </div>

            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>{t('scenarios.sigma.heading')}</div>
              <p className="mb-2 text-[11px] leading-snug" style={{ color: 'var(--muted)' }}>
                {sigma ? sigma.honesty_note : t('scenarios.sigma.honesty')}
              </p>
              {sigmaLoading && (
                <div className="flex items-center gap-2 py-2" style={{ color: 'var(--muted)' }}>
                  <span className="w-4 h-4 rounded-full border-2 animate-spin"
                    style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
                    aria-label={t('scenarios.sigma.loading')} />
                  {t('scenarios.sigma.loading')}
                </div>
              )}
              {sigmaError && <p role="alert" style={{ color: '#ffb4ab' }}>{sigmaError}</p>}
              {sigma && (
                <div className="rounded-lg border p-2 space-y-2"
                  style={{ background: 'var(--bg)', borderColor: 'var(--border)' }}>
                  <div className="flex items-center justify-end gap-2">
                    <button
                      type="button"
                      aria-label={t('scenarios.sigma.copyAriaLabel')}
                      onClick={() => {
                        void navigator.clipboard.writeText(sigma.yaml).then(() => {
                          setCopied(true);
                          setTimeout(() => setCopied(false), 1200);
                        });
                      }}
                      className="btn-ghost px-2 py-1 text-xs"
                    >
                      {copied ? t('scenarios.sigma.copied') : t('scenarios.sigma.copy')}
                    </button>
                    <button
                      type="button"
                      aria-label={t('scenarios.sigma.downloadAriaLabel')}
                      onClick={() => downloadText(
                        `augur-sigma-${selectedMeta!.scenario_id}-${dateStamp()}.yml`,
                        sigma.yaml, 'text/yaml')}
                      className="btn-ghost px-2 py-1 text-xs"
                    >
                      {t('scenarios.sigma.download')}
                    </button>
                  </div>
                  <pre className="whitespace-pre-wrap break-all font-mono text-[10px]"
                    style={{ color: 'var(--fg)', margin: 0 }}>
                    {sigma.yaml}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
