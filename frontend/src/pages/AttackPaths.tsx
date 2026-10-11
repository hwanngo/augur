import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Activity, CircleDashed, ShieldAlert, AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, ApiError } from '../lib/api';
import { CRIT_STYLE, toCrit } from '../lib/criticality';
import ExportCsvButton from '../components/ExportCsvButton';
import { toCsv, downloadCsv, dateStamp, type CsvColumn } from '../lib/csv';

// Lazy-load CytoscapeComponent so it stays out of the static dep graph (mirrors Pivot.tsx).
// Tests mock 'react-cytoscapejs'; the mock resolves synchronously so React.lazy settles at once.
const CytoscapeComponent = lazy(() => import('react-cytoscapejs'));

export type CyElement = { data: Record<string, unknown>; classes?: string };

interface Stop {
  zone: string; scenario_id: string | null; scenario_name: string;
  tactic: string | null; severity: string | null;
  status: 'observed' | 'hypothetical';
  observed_proximity: number; matched_steps: number; total_steps: number; host: string | null;
}
interface AttackPath {
  entry: { zone: string };
  target: { hostname: string; zone: string; criticality: string };
  realized_pct: number; mean_observed_proximity: number;
  observed_stop_count: number; total_stop_count: number; max_severity: string | null;
  stops: Stop[]; honesty_note: string;
}
interface PathsResponse { paths: AttackPath[]; honesty_note: string; from: string; to: string }

interface ExportRow { path: AttackPath; stop: Stop; index: number }
const EXPORT_COLUMNS: CsvColumn<ExportRow>[] = [
  { header: 'entry_zone', value: (r) => r.path.entry.zone },
  { header: 'target', value: (r) => r.path.target.hostname },
  { header: 'target_criticality', value: (r) => r.path.target.criticality },
  { header: 'realized_pct', value: (r) => String(r.path.realized_pct) },
  { header: 'stop_index', value: (r) => String(r.index) },
  { header: 'zone', value: (r) => r.stop.zone },
  { header: 'scenario_id', value: (r) => r.stop.scenario_id ?? '' },
  { header: 'status', value: (r) => r.stop.status },
  { header: 'observed_proximity', value: (r) => String(r.stop.observed_proximity) },
  { header: 'matched_steps', value: (r) => String(r.stop.matched_steps) },
  { header: 'total_steps', value: (r) => String(r.stop.total_steps) },
];

/** Map the fetched attack-paths response into Cytoscape elements: one lane per CRITICAL
 *  target. Nodes are the ordered zone stops (last = crown-jewel target). Edges connect
 *  consecutive stops and carry the DOWNSTREAM stop's status/tactic/severity (observed →
 *  amber/realized; hypothetical → muted/dashed). Pure + exported for unit testing. */
export function toElements(data: PathsResponse): CyElement[] {
  const els: CyElement[] = [];
  data.paths.forEach((p, li) => {
    const lastIdx = p.stops.length - 1;
    p.stops.forEach((s, si) => {
      const isTarget = si === lastIdx;
      els.push({
        data: {
          id: `L${li}|S${si}`,
          lane: li,
          stopIndex: si,
          zone: s.zone,
          label: s.zone,
          node_type: isTarget ? 'target' : 'stop',
          status: s.status,
          is_target: isTarget,
          criticality: isTarget ? p.target.criticality : null,
          scenario_id: s.scenario_id,
          scenario_name: s.scenario_name,
          tactic: s.tactic,
          severity: s.severity,
          matched_steps: s.matched_steps,
          total_steps: s.total_steps,
          observed_proximity: s.observed_proximity,
          host: s.host,
        },
      });
    });
    for (let i = 0; i < lastIdx; i++) {
      const down = p.stops[i + 1];
      els.push({
        data: {
          id: `L${li}|E${i}`,
          source: `L${li}|S${i}`,
          target: `L${li}|S${i + 1}`,
          lane: li,
          status: down.status,
          tactic: down.tactic ?? '',
          label: down.tactic ?? '',
          severity: down.severity,
        },
      });
    }
  });
  return els;
}

function critColor(c: string): string {
  return CRIT_STYLE[toCrit(c)].bg;
}
function critFg(c: string): string {
  return CRIT_STYLE[toCrit(c)].fg;
}

const STYLESHEET = [
  // Base zone stop: a pill whose zone name is centered INSIDE it (mirrors the Pivot graph).
  { selector: 'node', style: {
      label: 'data(label)', 'text-valign': 'center', 'text-halign': 'center',
      'text-wrap': 'wrap', 'text-max-width': 130, 'font-size': 11, 'font-weight': 600,
      color: '#e6edf3', 'background-color': '#1c2330',
      shape: 'round-rectangle', 'corner-radius': 10, width: 'label', height: 'label', padding: '12px',
      'border-width': 1.5, 'border-color': '#3d444d',
      'transition-property': 'border-color, background-color', 'transition-duration': '150ms',
    } },
  // observed stop = amber accent border (a realized progression)
  { selector: 'node[status = "observed"]', style: { 'border-width': 3, 'border-color': '#F59E0B' } },
  // crown-jewel target = octagon, criticality fill + AA-safe light text, light accent border.
  { selector: 'node[?is_target]', style: {
      shape: 'octagon', 'font-size': 12, 'font-weight': 700, padding: '18px',
      'border-width': 3, 'border-color': '#ffb4ab',
      color: (ele: { data: (k: string) => string }) => critFg(ele.data('criticality')),
      'background-color': (ele: { data: (k: string) => string }) => critColor(ele.data('criticality')),
    } },
  // Edges: dashed/muted = hypothetical. Tactic label sits in a chip so it never overlaps the line.
  { selector: 'edge', style: {
      label: 'data(label)', 'font-size': 9, 'font-weight': 700, color: '#cdd9e5',
      'text-background-color': '#0d1117', 'text-background-opacity': 0.95, 'text-background-padding': '4px',
      'text-background-shape': 'round-rectangle', 'text-border-color': '#30363d', 'text-border-width': 1,
      'text-border-opacity': 1,
      width: 1.4, 'line-color': '#444c56', 'target-arrow-color': '#444c56', 'arrow-scale': 1,
      'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'line-style': 'dashed',
    } },
  // edge into an observed zone = amber, thick, solid (realized)
  { selector: 'edge[status = "observed"]', style: {
      'line-color': '#F59E0B', 'target-arrow-color': '#F59E0B', width: 3, 'line-style': 'solid' } },
];

export default function AttackPaths() {
  const { t } = useTranslation();
  // Snapshot t into a ref so the fetch effect can reference it without t being a dep
  // (the i18n function reference may change when the locale loads, but should never retrigger fetch).
  const tRef = useRef(t);
  tRef.current = t;

  const [searchParams, setSearchParams] = useSearchParams();
  const view: 'graph' | 'table' = searchParams.get('view') === 'table' ? 'table' : 'graph';
  const VIEW_OPTIONS = ['graph', 'table'] as const;
  const setView = useCallback((v: 'graph' | 'table') => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (v === 'graph') next.delete('view'); else next.set('view', v);
      return next;
    });
  }, [setSearchParams]);

  // Roving-tabindex refs: one per option in VIEW_OPTIONS order.
  const radioRefs = useRef<Array<HTMLButtonElement | null>>([null, null]);

  const [data, setData] = useState<PathsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<PathsResponse>('/api/attack_paths?min_proximity=0.30')
      .then((d) => { setData(d); setLoading(false); })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : tRef.current('attackPaths.failedLoad'));
        setLoading(false);
      });
   
  }, []);

  const elements = useMemo(() => (data ? toElements(data) : []), [data]);
  const cyLayout = useMemo(
    () => ({ name: 'breadthfirst', directed: true, animate: false, spacingFactor: 1.4,
             padding: 32, nodeDimensionsIncludeLabels: true }),
    []
  );

  const onExport = () => {
    if (!data) return;
    const rows: ExportRow[] = [];
    data.paths.forEach((p) => p.stops.forEach((s, i) => rows.push({ path: p, stop: s, index: i })));
    downloadCsv(`augur-attack-paths-${dateStamp()}.csv`, toCsv(rows, EXPORT_COLUMNS));
  };

  return (
    <div className="w-full max-w-(--breakpoint-2xl) mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{t('attackPaths.title')}</h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{t('attackPaths.subtitle')}</p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {data && data.paths.length > 0 && (
            <div role="radiogroup" aria-label={t('attackPaths.viewToggleLabel')}
                 className="inline-flex rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
              {VIEW_OPTIONS.map((v, idx) => {
                const active = view === v;
                return (
                  <button
                    key={v}
                    ref={(el) => { radioRefs.current[idx] = el; }}
                    type="button"
                    role="radio"
                    aria-checked={active}
                    aria-label={t(`attackPaths.view.${v}`)}
                    tabIndex={active ? 0 : -1}
                    onClick={() => setView(v)}
                    onKeyDown={(e) => {
                      const isNext = e.key === 'ArrowRight' || e.key === 'ArrowDown';
                      const isPrev = e.key === 'ArrowLeft' || e.key === 'ArrowUp';
                      if (!isNext && !isPrev) return;
                      e.preventDefault();
                      const currentIdx = VIEW_OPTIONS.indexOf(view);
                      const nextIdx = isNext
                        ? (currentIdx + 1) % VIEW_OPTIONS.length
                        : (currentIdx - 1 + VIEW_OPTIONS.length) % VIEW_OPTIONS.length;
                      const nextView = VIEW_OPTIONS[nextIdx];
                      setView(nextView);
                      radioRefs.current[nextIdx]?.focus();
                    }}
                    className="py-1.5 px-3 text-xs focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                    style={{
                      background: active ? 'var(--accent)' : 'var(--panel)',
                      color: active ? '#0d1117' : 'var(--muted)',
                    }}
                  >
                    {t(`attackPaths.view.${v}`)}
                  </button>
                );
              })}
            </div>
          )}
          {data && data.paths.length > 0 && <ExportCsvButton onExport={onExport} label={t('attackPaths.export')} />}
        </div>
      </div>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div className="w-6 h-6 rounded-full border-2 animate-spin"
               style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }} aria-label={t('attackPaths.loading')} />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>{t('attackPaths.loading')}</span>
        </div>
      )}
      {error && (
        <div className="rounded-xl border p-4 flex items-center gap-3"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }} role="alert">
          <AlertTriangle size={16} aria-hidden /> {error}
        </div>
      )}
      {data && !error && data.paths.length === 0 && (
        <div className="text-center py-16"><p className="text-sm" style={{ color: 'var(--muted)' }}>{t('attackPaths.empty')}</p></div>
      )}

      {data && !error && view === 'graph' && data.paths.length > 0 && (
        <div className="space-y-4">
          {/* Per-lane summary — real DOM so the graph identity is screen-reader reachable */}
          <ul className="space-y-1">
            {data.paths.map((p) => (
              <li key={`${p.entry.zone}->${p.target.hostname}`}
                  className="flex items-center gap-2 text-xs" style={{ color: 'var(--fg)' }}>
                <ShieldAlert size={13} aria-hidden style={{ color: '#ffb4ab' }} />
                <span className="font-mono">{p.target.hostname}</span>
                <span className="px-2 py-0.5 rounded-full text-xs font-bold uppercase"
                      style={{ background: '#71221c', color: '#ffb4ab' }}>{p.target.criticality}</span>
                <span style={{ color: 'var(--muted)' }}>
                  · {t('attackPaths.realized', { pct: Math.round(p.realized_pct * 100) })}
                  · {t('attackPaths.entry')}: {p.entry.zone}
                  {p.max_severity ? ` · ${p.max_severity}` : ''}
                </span>
              </li>
            ))}
          </ul>

          {/* Cytoscape canvas — role=img + aria summary; the table toggle is the SR data path */}
          <div className="rounded-xl border overflow-hidden"
               style={{ borderColor: 'var(--border)', height: 560 }}
               role="img"
               aria-label={t('attackPaths.graphAria', {
                 targets: data.paths.length,
                 observed: data.paths.reduce((n, p) => n + p.observed_stop_count, 0),
               })}>
            <Suspense fallback={
              <div className="w-full h-full flex items-center justify-center">
                <span className="text-sm" style={{ color: 'var(--muted)' }}>{t('attackPaths.loading')}</span>
              </div>
            }>
              <CytoscapeComponent
                elements={elements as never}
                stylesheet={STYLESHEET as never}
                layout={cyLayout as never}
                style={{ width: '100%', height: '100%' }}
              />
            </Suspense>
          </div>

          {/* Legend — real DOM */}
          <div className="text-xs flex flex-wrap gap-4 items-center" style={{ color: 'var(--muted)' }}>
            <span className="font-semibold">{t('attackPaths.legend')}:</span>
            <span className="inline-flex items-center gap-1">
              <span style={{ width: 14, height: 0, borderTop: '3px solid #F59E0B', display: 'inline-block' }} />
              {t('attackPaths.legendRealized')}
            </span>
            <span className="inline-flex items-center gap-1">
              <span style={{ width: 14, height: 0, borderTop: '1px dashed #8b949e', display: 'inline-block' }} />
              {t('attackPaths.legendHypothetical')}
            </span>
            <span className="inline-flex items-center gap-1">
              <span style={{ width: 10, height: 10, borderRadius: 2, background: CRIT_STYLE.CRITICAL.bg,
                             border: '1px solid #ffb4ab', display: 'inline-block' }} />
              {t('attackPaths.legendTarget')}
            </span>
            <span className="inline-flex items-center gap-1">
              <span style={{ width: 10, height: 10, borderRadius: 2, background: '#161b22',
                             border: '1px solid #8b949e', display: 'inline-block' }} />
              {t('attackPaths.legendStop')}
            </span>
          </div>

          {/* Honesty panel — real DOM, shown in graph view */}
          <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{data.honesty_note}</p>
        </div>
      )}

      {data && !error && view === 'table' && data.paths.map((p) => (
        <div key={`${p.entry.zone}->${p.target.hostname}`} className="rounded-xl border overflow-hidden"
             style={{ borderColor: 'var(--border)' }}>
          <div className="px-4 py-3 flex items-center justify-between flex-wrap gap-3" style={{ background: 'var(--panel)' }}>
            <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--fg)' }}>
              <ShieldAlert size={15} aria-hidden style={{ color: '#ffb4ab' }} />
              <span className="font-mono">{p.target.hostname}</span>
              <span className="px-2 py-0.5 rounded-full text-xs font-bold uppercase"
                    style={{ background: '#71221c', color: '#ffb4ab' }}>{p.target.criticality}</span>
              <span className="text-xs" style={{ color: 'var(--muted)' }}>· {t('attackPaths.entry')}: {p.entry.zone}</span>
            </div>
            <div className="flex items-center gap-2 min-w-[160px]">
              <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
                <div className="h-full" style={{ width: `${Math.round(p.realized_pct * 100)}%`, background: 'var(--accent)' }} />
              </div>
              <span className="text-xs tabular-nums" style={{ color: 'var(--fg)' }}>
                {t('attackPaths.realized', { pct: Math.round(p.realized_pct * 100) })}
              </span>
            </div>
          </div>
          <ol className="px-4 py-3 space-y-2">
            {p.stops.map((s, i) => {
              const obs = s.status === 'observed';
              const tone = obs ? '#7ee787' : '#8b949e';
              return (
                <li key={`${s.zone}-${i}`} className="flex items-center gap-3">
                  {obs ? <Activity size={14} style={{ color: tone }} aria-hidden />
                       : <CircleDashed size={14} style={{ color: tone }} aria-hidden />}
                  <span className="text-xs w-36 shrink-0" style={{ color: 'var(--fg)' }}>{s.zone}</span>
                  <span className="text-xs flex-1 truncate" style={{ color: 'var(--muted)' }}>
                    {s.scenario_id ? s.scenario_name : t('attackPaths.noCoverage')}
                    {s.host ? ` · ${s.host}` : ''}
                  </span>
                  <span className="text-xs tabular-nums" style={{ color: tone }}>
                    {s.matched_steps}/{s.total_steps} · {s.observed_proximity.toFixed(2)} · {obs ? t('attackPaths.observed') : t('attackPaths.hypothetical')}
                  </span>
                </li>
              );
            })}
          </ol>
          <p className="px-4 pb-3 text-xs italic" style={{ color: 'var(--muted)' }}>{p.honesty_note}</p>
        </div>
      ))}
    </div>
  );
}
