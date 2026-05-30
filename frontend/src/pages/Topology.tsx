import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ChevronUp, ChevronDown, Minus, AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { apiGet, ApiError } from '../lib/api';
import SearchInput from '../components/SearchInput';
import Dropdown from '../components/Dropdown';
import Pagination from '../components/Pagination';
import DetailDrawer from '../components/DetailDrawer';
import { usePagination } from '../lib/usePagination';
import { CRIT_STYLE, CritChip, toCrit, type Crit } from '../lib/criticality';

// Lazy-load CytoscapeComponent so it stays out of the static dep graph (mirrors Pivot/AttackPaths).
const CytoscapeComponent = lazy(() => import('react-cytoscapejs'));

const PAGE_SIZE = 12;

/* ──────────────────────────── Types ─────────────────────────────────────── */
export interface Asset {
  hostname: string;
  zone: string;
  criticality: Crit;
  os: string;
  ip: string;
  role: string;
}

interface TopologyResponse {
  zones: string[];
  assets: Asset[];
}

export type CyElement = { data: Record<string, unknown>; classes?: string; position?: { x: number; y: number } };

function critBg(c: string): string { return CRIT_STYLE[toCrit(c)].bg; }
function critFg(c: string): string { return CRIT_STYLE[toCrit(c)].fg; }

/** Map the topology into Cytoscape elements: each zone is a compound container node, each host a
 *  criticality-filled child pill inside its zone. No host-to-host edges — the topology models zone
 *  membership + criticality, not network adjacency (see the honesty note). Hosts get explicit preset
 *  positions (zones laid out left-to-right as columns, hosts stacked within) so the compound layout is
 *  deterministic and never overlaps; zone parents auto-size around their children. Pure + unit-tested. */
const COL_W = 300;
const ROW_H = 78;
export function toElements(data: TopologyResponse): CyElement[] {
  const els: CyElement[] = [];
  const byZone = new Map<string, Asset[]>();
  for (const a of data.assets) {
    if (!byZone.has(a.zone)) byZone.set(a.zone, []);
    byZone.get(a.zone)!.push(a);
  }
  const zones = [...byZone.keys()].sort();
  zones.forEach((z, zi) => {
    els.push({ data: { id: `zone:${z}`, label: z, node_type: 'zone' }, classes: 'zone' });
    const hosts = byZone.get(z)!.slice().sort((a, b) => (a.hostname < b.hostname ? -1 : 1));
    hosts.forEach((a, hi) => {
      els.push({
        data: {
          id: `host:${a.hostname}`, parent: `zone:${z}`, label: a.hostname, node_type: 'host',
          criticality: a.criticality, zone: a.zone, os: a.os, ip: a.ip, role: a.role,
        },
        position: { x: zi * COL_W, y: hi * ROW_H },
      });
    });
  });
  return els;
}

const STYLESHEET = [
  // Zone = compound container, name across the top.
  { selector: ':parent', style: {
      label: 'data(label)', 'text-valign': 'top', 'text-halign': 'center', 'text-margin-y': -2,
      'font-size': 11, 'font-weight': 700, color: '#9fb0c3', 'text-transform': 'uppercase',
      'background-color': '#11161f', 'background-opacity': 0.55, shape: 'round-rectangle',
      'corner-radius': 14, 'border-width': 1, 'border-color': '#30363d', padding: '20px',
    } },
  // Host = criticality-filled pill, hostname centered INSIDE (mirrors the Pivot graph).
  { selector: 'node[node_type = "host"]', style: {
      label: 'data(label)', 'text-valign': 'center', 'text-halign': 'center',
      'text-wrap': 'wrap', 'text-max-width': 140, 'font-size': 10, 'font-weight': 600,
      color: (ele: { data: (k: string) => string }) => critFg(ele.data('criticality')),
      'background-color': (ele: { data: (k: string) => string }) => critBg(ele.data('criticality')),
      shape: 'round-rectangle', 'corner-radius': 8, width: 'label', height: 'label', padding: '9px',
      'border-width': 1, 'border-color': '#30363d',
      'transition-property': 'border-color, border-width', 'transition-duration': '150ms',
    } },
  // CRITICAL hosts get a light accent ring; the selected host a brighter one.
  { selector: 'node[node_type = "host"][criticality = "CRITICAL"]', style: { 'border-color': '#ffb4ab', 'border-width': 2 } },
  { selector: 'node.selected', style: { 'border-color': '#58a6ff', 'border-width': 3 } },
];

/* ──────────────────────────── Sorting ───────────────────────────────────── */
type SortKey = keyof Asset;
type SortDir = 'asc' | 'desc';

const CRIT_ORDER: Record<Asset['criticality'], number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1,
};

/* ──────────────────────────── Topology page ─────────────────────────────── */
export default function Topology() {
  const { t } = useTranslation();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [zones, setZones] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>('criticality');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [query, setQuery] = useState('');
  const [zoneFilter, setZoneFilter] = useState('');

  const [searchParams, setSearchParams] = useSearchParams();
  const selectedHost = searchParams.get('host');
  const selectAsset = (hostname: string | null) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (hostname) next.set('host', hostname); else next.delete('host');
      return next;
    });
  };
  const selected = assets.find((a) => a.hostname === selectedHost) ?? null;

  // Graph / Table view toggle (graph default). Mirrors the Attack Paths radiogroup.
  const view: 'graph' | 'table' = searchParams.get('view') === 'table' ? 'table' : 'graph';
  const VIEW_OPTIONS = ['graph', 'table'] as const;
  const radioRefs = useRef<Array<HTMLButtonElement | null>>([null, null]);
  const setView = useCallback((v: 'graph' | 'table') => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (v === 'graph') next.delete('view'); else next.set('view', v);
      return next;
    });
  }, [setSearchParams]);

  useEffect(() => {
    apiGet<TopologyResponse>('/api/topology')
      .then((data) => { setAssets(data.assets); setZones(data.zones ?? []); setLoading(false); })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : t('topology.failedLoad'));
        setLoading(false);
      });
  }, [t]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir('asc'); }
  };

  const q = query.trim().toLowerCase();
  const filtered = assets.filter((a) => {
    if (zoneFilter && a.zone !== zoneFilter) return false;
    if (!q) return true;
    return (
      a.hostname.toLowerCase().includes(q) ||
      a.ip.toLowerCase().includes(q) ||
      a.os.toLowerCase().includes(q) ||
      a.role.toLowerCase().includes(q) ||
      a.zone.toLowerCase().includes(q)
    );
  });

  const sorted = [...filtered].sort((a, b) => {
    let cmp = 0;
    if (sortKey === 'criticality') {
      cmp = CRIT_ORDER[a.criticality] - CRIT_ORDER[b.criticality];
    } else {
      cmp = String(a[sortKey]) < String(b[sortKey]) ? -1 : String(a[sortKey]) > String(b[sortKey]) ? 1 : 0;
    }
    return sortDir === 'asc' ? cmp : -cmp;
  });

  const { page, setPage, pageCount, pageItems, total, start, end } = usePagination(sorted, PAGE_SIZE);

  // Graph elements honor the same search/zone filter as the table.
  const cyElements = useMemo(() => toElements({ zones, assets: filtered }), [zones, filtered]);
  // Preset: hosts carry explicit positions (zone columns); zone parents auto-wrap their children.
  const cyLayout = useMemo(() => ({ name: 'preset', fit: true, padding: 40 }), []);

  function SortIcon({ col }: { col: SortKey }) {
    if (sortKey !== col) return <Minus size={12} className="opacity-30" aria-hidden />;
    return sortDir === 'asc'
      ? <ChevronUp size={12} aria-hidden />
      : <ChevronDown size={12} aria-hidden />;
  }

  function Th({ col, label }: { col: SortKey; label: string }) {
    return (
      <th
        className="px-3 py-2.5 text-left text-xs font-medium cursor-pointer select-none whitespace-nowrap transition-colors hover:text-[var(--fg)]"
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
    <div className="w-full max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            {t('topology.title')}
          </h1>
          {!loading && !error && (
            <p className="text-xs mt-0.5 tabular-nums" style={{ color: 'var(--muted)' }}>
              {t('topology.assetCount', { count: assets.length })}
            </p>
          )}
        </div>
        {!loading && !error && (
          <div className="flex items-center gap-2 flex-wrap">
            <SearchInput value={query} onChange={setQuery} label={t('common.search')} placeholder={t('topology.search')} />
            <Dropdown
              value={zoneFilter}
              onChange={setZoneFilter}
              aria-label={t('topology.table.zone')}
              options={[
                { value: '', label: t('common.allZones') },
                ...zones.map((z) => ({ value: z, label: z })),
              ]}
            />
            <div role="radiogroup" aria-label={t('topology.viewToggleLabel')}
                 className="inline-flex rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
              {VIEW_OPTIONS.map((v, idx) => {
                const active = view === v;
                return (
                  <button
                    key={v}
                    ref={(el) => { radioRefs.current[idx] = el; }}
                    type="button" role="radio" aria-checked={active}
                    aria-label={t(`topology.view.${v}`)}
                    tabIndex={active ? 0 : -1}
                    onClick={() => setView(v)}
                    onKeyDown={(e) => {
                      const isNext = e.key === 'ArrowRight' || e.key === 'ArrowDown';
                      const isPrev = e.key === 'ArrowLeft' || e.key === 'ArrowUp';
                      if (!isNext && !isPrev) return;
                      e.preventDefault();
                      const cur = VIEW_OPTIONS.indexOf(view);
                      const nextIdx = isNext ? (cur + 1) % VIEW_OPTIONS.length
                                             : (cur - 1 + VIEW_OPTIONS.length) % VIEW_OPTIONS.length;
                      setView(VIEW_OPTIONS[nextIdx]);
                      radioRefs.current[nextIdx]?.focus();
                    }}
                    className="py-1.5 px-3 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
                    style={{ background: active ? 'var(--accent)' : 'var(--panel)', color: active ? '#0d1117' : 'var(--muted)' }}
                  >
                    {t(`topology.view.${v}`)}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('topology.loading')}
          />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('topology.loading')}
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

      {!loading && !error && assets.length === 0 && (
        <div className="text-center py-16">
          <p className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('topology.empty')}
          </p>
        </div>
      )}

      {/* Graph view — zones as compound containers, hosts as criticality pills; click a host to drill in */}
      {!loading && !error && assets.length > 0 && view === 'graph' && (
        <div className="space-y-4">
          <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)', height: 600 }}
               role="img" aria-label={t('topology.graphAria', { count: filtered.length, zones: new Set(filtered.map((a) => a.zone)).size })}>
            {filtered.length === 0 ? (
              <div className="w-full h-full flex items-center justify-center">
                <span className="text-sm" style={{ color: 'var(--muted)' }}>{t('common.noMatches')}</span>
              </div>
            ) : (
              <Suspense fallback={
                <div className="w-full h-full flex items-center justify-center">
                  <span className="text-sm" style={{ color: 'var(--muted)' }}>{t('topology.loading')}</span>
                </div>
              }>
                <CytoscapeComponent
                  key={selectedHost ?? ''}
                  elements={cyElements as never}
                  stylesheet={STYLESHEET as never}
                  layout={cyLayout as never}
                  style={{ width: '100%', height: '100%' }}
                  cy={(cy: { on: (ev: string, sel: string, cb: (e: { target: { id: () => string } }) => void) => void; nodes: (sel: string) => { addClass: (c: string) => void } }) => {
                    cy.on('tap', 'node[node_type = "host"]', (evt) => {
                      selectAsset(evt.target.id().replace(/^host:/, ''));
                    });
                    if (selectedHost) cy.nodes(`[id = "host:${selectedHost}"]`).addClass('selected');
                  }}
                />
              </Suspense>
            )}
          </div>
          {/* Legend + honesty */}
          <div className="text-xs flex flex-wrap items-center gap-x-4 gap-y-2" style={{ color: 'var(--muted)' }}>
            <span className="font-semibold">{t('attackPaths.legend')}:</span>
            <span>{t('topology.legendFill')}</span>
            <span className="flex items-center gap-1.5">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const).map((c) => (
                <span key={c} className="inline-flex items-center gap-1">
                  <span style={{ width: 14, height: 10, borderRadius: 3, background: CRIT_STYLE[c].bg, border: '1px solid #30363d', display: 'inline-block' }} />
                  {c}
                </span>
              ))}
            </span>
          </div>
          <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{t('topology.honesty')}</p>
        </div>
      )}

      {!loading && !error && assets.length > 0 && view === 'table' && (
        <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
          <table className="w-full min-w-[720px] text-sm" aria-label={t('topology.ariaLabel')}>
            <thead style={{ background: 'var(--panel)' }}>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <Th col="hostname" label={t('topology.table.hostname')} />
                <Th col="zone" label={t('topology.table.zone')} />
                <Th col="criticality" label={t('topology.table.criticality')} />
                <Th col="os" label={t('topology.table.os')} />
                <Th col="ip" label={t('topology.table.ip')} />
                <Th col="role" label={t('topology.table.role')} />
              </tr>
            </thead>
            <tbody>
              {pageItems.map((asset) => (
                <tr
                  key={asset.hostname}
                  className="transition-colors hover:bg-[#1e242c]"
                  style={{
                    borderBottom: '1px solid var(--border)',
                    background: selectedHost === asset.hostname ? '#1b2129' : undefined,
                  }}
                >
                  <td className="px-3 py-2.5">
                    <button
                      type="button"
                      onClick={() => selectAsset(asset.hostname)}
                      aria-current={selectedHost === asset.hostname}
                      aria-label={t('topology.detail.open', { name: asset.hostname })}
                      className="font-medium font-mono text-xs text-left cursor-pointer hover:underline focus:underline focus:outline-none"
                      style={{
                        color: 'var(--fg)',
                        boxShadow:
                          selectedHost === asset.hostname
                            ? 'inset 2px 0 0 0 var(--accent)'
                            : undefined,
                      }}
                    >
                      {asset.hostname}
                    </button>
                  </td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--muted)' }}>
                    {asset.zone}
                  </td>
                  <td className="px-3 py-2.5">
                    <CritChip level={asset.criticality} />
                  </td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--fg)' }}>
                    {asset.os}
                  </td>
                  <td className="px-3 py-2.5 text-xs tabular-nums font-mono" style={{ color: 'var(--muted)' }}>
                    {asset.ip}
                  </td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--muted)' }}>
                    {asset.role}
                  </td>
                </tr>
              ))}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-sm" style={{ color: 'var(--muted)' }}>
                    {t('common.noMatches')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {!loading && !error && assets.length > 0 && view === 'table' && (
        <Pagination page={page} pageCount={pageCount} total={total} start={start} end={end} onPage={setPage} />
      )}

      <DetailDrawer
        open={!!selected}
        title={selected ? t('topology.detail.title', { name: selected.hostname }) : ''}
        onClose={() => selectAsset(null)}
      >
        {selected && (
          <dl className="space-y-3 text-xs">
            <div>
              <dt className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('topology.detail.hostname')}</dt>
              <dd className="font-mono mt-0.5" style={{ color: 'var(--fg)' }}>{selected.hostname}</dd>
            </div>
            <div>
              <dt className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('topology.detail.zone')}</dt>
              <dd className="mt-0.5" style={{ color: 'var(--fg)' }}>{selected.zone}</dd>
            </div>
            <div>
              <dt className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('topology.detail.criticality')}</dt>
              <dd className="mt-1"><CritChip level={selected.criticality} /></dd>
            </div>
            <div>
              <dt className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('topology.detail.os')}</dt>
              <dd className="mt-0.5" style={{ color: 'var(--fg)' }}>{selected.os}</dd>
            </div>
            <div>
              <dt className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('topology.detail.ip')}</dt>
              <dd className="font-mono mt-0.5" style={{ color: 'var(--fg)' }}>{selected.ip}</dd>
            </div>
            <div>
              <dt className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('topology.detail.role')}</dt>
              <dd className="mt-0.5" style={{ color: 'var(--fg)' }}>{selected.role}</dd>
            </div>
          </dl>
        )}
      </DetailDrawer>
    </div>
  );
}
