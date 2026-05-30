import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { AlertTriangle, GitFork, ChevronRight } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, ApiError } from '../lib/api';

// Lazy-load CytoscapeComponent so it is NOT in the static dep graph of this module.
// Tests mock 'react-cytoscapejs' via vi.mock() and vitest intercepts before the
// dynamic import resolves, keeping the heavy canvas library out of the test bundle.
const CytoscapeComponent = lazy(() => import('react-cytoscapejs'));
import { CRIT_STYLE, toCrit } from '../lib/criticality';
import ExportCsvButton from '../components/ExportCsvButton';
import ErrorBoundary from '../components/ErrorBoundary';
import Dropdown from '../components/Dropdown';
import { SevChip, type Detection } from '../components/DetectionCard';
import { toCsv, downloadCsv, dateStamp, type CsvColumn } from '../lib/csv';

interface PivotNode {
  id: string; node_type: 'Host' | 'Process' | 'File'; label: string; host: string;
  criticality: string; zone: string; seed: boolean; hop: number;
  name?: string; command?: string; integrity_level?: string;
  path?: string; is_signed?: boolean; is_injected?: boolean; extension?: string;
}
interface PivotEdge {
  id: string; src: string; dst: string; edge_type: string; timestamp: string; is_injected?: boolean;
}
interface PivotResponse {
  seed: { scenario_id: string; name: string; severity: string; seed_node_ids: string[]; affected_hosts: string[] };
  nodes: PivotNode[];
  edges: PivotEdge[];
  summary: {
    node_count: number; edge_count: number; nodes_total: number; edges_total: number;
    nodes_truncated: boolean; edges_truncated: boolean; hops: number; honesty_note: string;
  };
}

export type CyElement = { data: Record<string, unknown>; classes?: string };

// Minimal structural type for the Cytoscape core + collections we touch (the real lib is lazy-loaded).
type CyColl = { addClass: (c: string) => void; removeClass: (c: string) => void };
type CyNode = {
  id: () => string;
  closedNeighborhood: () => CyColl;
  connectedEdges: () => CyColl;
};
type CyCore = {
  on: (ev: string, sel: string, cb: (e: { target: CyNode }) => void) => void;
  batch: (fn: () => void) => void;
  elements: () => CyColl;
  edges: () => CyColl;
};

const NODE_EXPORT: CsvColumn<PivotNode>[] = [
  { header: 'id', value: (n) => n.id },
  { header: 'node_type', value: (n) => n.node_type },
  { header: 'label', value: (n) => n.label },
  { header: 'host', value: (n) => n.host },
  { header: 'criticality', value: (n) => n.criticality },
  { header: 'hop', value: (n) => String(n.hop) },
  { header: 'seed', value: (n) => (n.seed ? 'true' : 'false') },
];

/** Display label: basename a path-like name (real Sysmon sets ProcessName to the full image PATH,
 *  so the in-node pill would otherwise read "C:\Windows\System32\…"). Host/basename labels pass through.
 *  The full value is preserved on the node data (and in the CSV export). */
export function displayLabel(label: string): string {
  if (!label.includes('\\') && !label.includes('/')) return label;
  const parts = label.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : label;
}

/** Map the API result into Cytoscape elements. Deeper-than-1 hops start hidden until tapped. */
export function toElements(data: PivotResponse): CyElement[] {
  const nodes: CyElement[] = data.nodes.map((n) => ({
    data: { ...n, label: displayLabel(n.label) },
    classes: n.hop > 1 ? 'hidden' : '',
  }));
  const edges: CyElement[] = data.edges.map((e) => ({
    data: { id: e.id, source: e.src, target: e.dst, label: e.edge_type,
            edge_type: e.edge_type, is_injected: e.is_injected ?? false },
    classes: 'hidden',  // edges reveal as their endpoints reveal (seed 1-hop revealed below)
  }));
  // Reveal the seed nodes' 1-hop edges up front.
  const seedSet = new Set(data.seed.seed_node_ids);
  for (const e of edges) {
    if (seedSet.has(e.data.source as string) || seedSet.has(e.data.target as string)) {
      e.classes = '';
    }
  }
  return [...nodes, ...edges];
}

/** Client-side pivot: un-hide the tapped node's direct neighbors (nodes + connecting edges). */
export function revealNeighbors(elements: CyElement[], nodeId: string): CyElement[] {
  const unhide = (c?: string) => (c ?? '').split(/\s+/).filter((x) => x && x !== 'hidden').join(' ');
  const touched = new Set<string>();
  const next = elements.map((el) => {
    const { source, target, id } = el.data as { source?: string; target?: string; id?: string };
    if (source === nodeId || target === nodeId) {
      if (source) touched.add(source);
      if (target) touched.add(target);
      return { ...el, classes: unhide(el.classes) };
    }
    if (id === nodeId) return { ...el, classes: unhide(el.classes) };
    return el;
  });
  return next.map((el) => {
    const id = (el.data as { id?: string; source?: string }).id;
    const isNode = !(el.data as { source?: string }).source;
    if (isNode && id && touched.has(id)) return { ...el, classes: unhide(el.classes) };
    return el;
  });
}

function critBg(c: string): string {
  return CRIT_STYLE[toCrit(c)].bg;
}
function critFg(c: string): string {
  return CRIT_STYLE[toCrit(c)].fg;
}

/** Module File nodes = LOADED libraries that are not injected — the system-DLL noise we collapse by default.
 *  Injected files stay visible (they are the interesting artifact). */
export function moduleNodeIds(data: PivotResponse): Set<string> {
  const fileById = new Map(data.nodes.filter((n) => n.node_type === 'File').map((n) => [n.id, n] as const));
  const ids = new Set<string>();
  for (const e of data.edges) {
    if (e.edge_type !== 'LOADED') continue;
    const f = fileById.get(e.dst);
    if (f && !f.is_injected) ids.add(f.id);
  }
  return ids;
}

/** Toggle module visibility on module nodes + any edge touching one. When hiding, add `module-hidden`
 *  (resolves to display:none). When showing, clear BOTH `module-hidden` and the hop-depth `.hidden` so
 *  modules reveal fully regardless of BFS hop (most loaded DLLs sit at hop ≥ 2). Pure / testable. */
export function applyModuleHidden(elements: CyElement[], moduleIds: Set<string>, show: boolean): CyElement[] {
  return elements.map((el) => {
    const d = el.data as { id?: string; source?: string; target?: string };
    const touches = d.source
      ? moduleIds.has(d.source) || moduleIds.has(d.target as string)
      : moduleIds.has(d.id as string);
    if (!touches) return el;
    const classes = new Set((el.classes ?? '').split(/\s+/).filter(Boolean));
    if (show) { classes.delete('module-hidden'); classes.delete('hidden'); }
    else { classes.add('module-hidden'); }
    return { ...el, classes: [...classes].join(' ') };
  });
}

const STYLESHEET = [
  // Base node: a pill whose name is centered INSIDE it; fill+text are the AA-safe criticality pair.
  { selector: 'node', style: {
      label: 'data(label)', 'text-valign': 'center', 'text-halign': 'center',
      'text-wrap': 'ellipsis', 'text-max-width': 150, 'font-size': 11, 'font-weight': 600,
      color: (ele: { data: (k: string) => string }) => critFg(ele.data('criticality')),
      'background-color': (ele: { data: (k: string) => string }) => critBg(ele.data('criticality')),
      shape: 'round-rectangle', 'corner-radius': 9, width: 'label', height: 'label', padding: '9px',
      'border-width': 1, 'border-color': '#30363d',
      'transition-property': 'background-opacity, text-opacity, border-color', 'transition-duration': '150ms',
    } },
  { selector: 'node[node_type = "Host"]', style: {
      'font-weight': 700, 'font-size': 12, 'border-width': 2, 'border-color': '#6e7681',
      'text-transform': 'uppercase' } },
  { selector: 'node[node_type = "File"]', style: { 'font-size': 10, 'border-style': 'dashed' } },
  { selector: 'node[?is_injected]', style: { 'border-color': '#f85149', 'border-width': 2, 'border-style': 'solid' } },
  { selector: 'node[?seed]', style: {
      'border-width': 2, 'border-color': '#58a6ff', 'font-size': 12, 'z-index': 10,
      'outline-width': 3, 'outline-color': '#1f6feb', 'outline-opacity': 0.5, 'outline-offset': 2 } },
  { selector: 'node.faded', style: { 'background-opacity': 0.18, 'text-opacity': 0.22, 'border-opacity': 0.2 } },
  { selector: '.hidden', style: { display: 'none' } },
  { selector: '.module-hidden', style: { display: 'none' } },
  // Edges: no label by default; type encoded by color + line style. Hover reveals the label (.elabel).
  { selector: 'edge', style: {
      width: 1.2, 'line-color': '#3d444d', 'curve-style': 'bezier', 'arrow-scale': 0.8,
      'target-arrow-color': '#3d444d', 'target-arrow-shape': 'triangle',
      'transition-property': 'line-color, width, opacity', 'transition-duration': '150ms' } },
  { selector: 'edge[edge_type = "SPAWNED"]', style: { 'line-color': '#539bf5', 'target-arrow-color': '#539bf5', width: 1.6 } },
  { selector: 'edge[edge_type = "EXHIBITED"]', style: { 'line-color': '#bc8cff', 'target-arrow-color': '#bc8cff', 'line-style': 'dashed' } },
  { selector: 'edge[edge_type = "RUNS_ON"]', style: { 'line-color': '#444c56', 'target-arrow-color': '#444c56', 'line-style': 'dotted' } },
  { selector: 'edge[edge_type = "LOADED"]', style: { 'line-color': '#2d333b', 'target-arrow-color': '#2d333b', width: 0.8 } },
  { selector: 'edge[?is_injected]', style: { 'line-color': '#f85149', 'target-arrow-color': '#f85149', 'line-style': 'dashed', width: 2 } },
  { selector: 'edge.faded', style: { opacity: 0.07 } },
  { selector: 'edge.elabel', style: {
      label: 'data(label)', 'font-size': 8, color: '#adbac7', 'text-rotation': 'autorotate',
      'text-background-color': '#161b22', 'text-background-opacity': 0.85, 'text-background-padding': '2px' } },
];

const LAYOUTS = ['cose', 'breadthfirst', 'concentric'] as const;
const HOPS = [1, 2, 3] as const;

/** Layout options tuned so label-sized pills do not overlap. */
function layoutOptions(name: string): Record<string, unknown> {
  const base = { name, animate: false, padding: 36, nodeDimensionsIncludeLabels: true };
  if (name === 'cose') return { ...base, nodeRepulsion: 9000, idealEdgeLength: 110, componentSpacing: 90, nestingFactor: 0.9 };
  if (name === 'concentric') return { ...base, minNodeSpacing: 44, concentric: (n: { data: (k: string) => number }) => 10 - (n.data('hop') ?? 0), levelWidth: () => 1 };
  return { ...base, spacingFactor: 1.3, directed: true };
}

/** Empty-state picker: reached when /pivot has no ?detection=. Lists current detections so the
 *  sidebar nav item is self-sufficient (no need to detour through the Dashboard). */
function PivotPicker() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [dets, setDets] = useState<Detection[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<Detection[]>('/api/detections')
      .then(setDets)
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : 'Failed to load detections'));
  }, []);

  const go = (id: string) => navigate(`/pivot?detection=${encodeURIComponent(id)}`);

  return (
    <div className="w-full max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
      <div className="flex items-center gap-2">
        <GitFork size={18} aria-hidden style={{ color: 'var(--accent)' }} />
        <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{t('pivot.title')}</h1>
      </div>
      <p className="text-sm" style={{ color: 'var(--muted)' }}>{t('pivot.pickPrompt')}</p>

      {error && (
        <div className="rounded-xl border p-3 flex items-center gap-2 text-sm" role="alert"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}>
          <AlertTriangle size={14} aria-hidden /> {error}
        </div>
      )}

      {dets && dets.length === 0 && !error && (
        <p className="text-sm" style={{ color: 'var(--muted)' }}>{t('pivot.noDetectionsYet')}</p>
      )}

      {dets && dets.length > 0 && (
        <ul className="space-y-1.5">
          {dets.map((d) => (
            <li key={d.scenario_id}>
              <button
                type="button"
                onClick={() => go(d.scenario_id)}
                className="w-full flex items-center gap-3 rounded-lg border px-3 py-2 text-left transition-colors hover:brightness-125"
                style={{ borderColor: 'var(--border)', background: 'var(--panel)' }}
              >
                <SevChip level={d.severity} />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm truncate" style={{ color: 'var(--fg)' }}>{d.name}</span>
                  <span className="block text-xs tabular-nums truncate" style={{ color: 'var(--muted)' }}>
                    {d.scenario_id} · {Math.round(d.proximity * 100)}% · {d.affected_hosts.join(', ') || '—'}
                  </span>
                </span>
                <ChevronRight size={16} aria-hidden style={{ color: 'var(--muted)' }} className="flex-shrink-0" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function Pivot() {
  const { t } = useTranslation();
  // Snapshot t into a ref so the fetch effect can use it without listing it as a dep
  // (the i18n function reference may change when the locale loads, but it is never the
  // trigger we want for re-fetching).
  const tRef = useRef(t);
  tRef.current = t;

  const [searchParams, setSearchParams] = useSearchParams();
  const detection = searchParams.get('detection')?.trim() ?? '';
  const hops = Number(searchParams.get('hops') ?? '2') || 2;

  const [data, setData] = useState<PivotResponse | null>(null);
  const [elements, setElements] = useState<CyElement[]>([]);
  const [layout, setLayout] = useState<(typeof LAYOUTS)[number]>('cose');
  const [showModules, setShowModules] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!detection) { setData(null); setElements([]); return; }
    setLoading(true);
    setError(null);
    setData(null);
    setShowModules(false);
    apiGet<PivotResponse>(`/api/pivot_graph?detection=${encodeURIComponent(detection)}&hops=${hops}`)
      .then((d) => { setData(d); setElements(toElements(d)); setLoading(false); })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : tRef.current('pivot.failedLoad'));
        setLoading(false);
      });

  }, [detection, hops]);

  const cyLayout = useMemo(() => layoutOptions(layout), [layout]);

  // System-module File nodes are collapsed by default to clear the DLL hairball.
  const moduleIds = useMemo(() => (data ? moduleNodeIds(data) : new Set<string>()), [data]);
  const shownElements = useMemo(
    () => applyModuleHidden(elements, moduleIds, showModules),
    [elements, moduleIds, showModules],
  );

  const onExport = () => {
    if (!data) return;
    downloadCsv(`augur-pivot-${dateStamp()}.csv`, toCsv(data.nodes, NODE_EXPORT));
  };

  const setHops = (h: number) => {
    const next = new URLSearchParams(searchParams);
    next.set('hops', String(h));
    setSearchParams(next);
  };

  if (!detection) return <PivotPicker />;

  return (
    <div className="w-full max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-4">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            {data ? data.seed.name : t('pivot.title')}
          </h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>
            {data
              ? `${data.seed.scenario_id} · ${data.summary.node_count} ${t('pivot.nodes')} · ${data.summary.edge_count} ${t('pivot.edges')}`
              : t('pivot.subtitle')}
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs flex items-center gap-1" style={{ color: 'var(--muted)' }}>
            {t('pivot.hops')}
            <Dropdown
              aria-label={t('pivot.hops')}
              value={String(hops)}
              onChange={(v) => setHops(Number(v))}
              options={HOPS.map((h) => ({ value: String(h), label: String(h) }))}
            />
          </label>
          <label className="text-xs flex items-center gap-1" style={{ color: 'var(--muted)' }}>
            {t('pivot.layout')}
            <Dropdown
              aria-label={t('pivot.layout')}
              value={layout}
              onChange={(v) => setLayout(v as (typeof LAYOUTS)[number])}
              options={LAYOUTS.map((l) => ({ value: l, label: l }))}
            />
          </label>
          {data && moduleIds.size > 0 && (
            <button
              type="button"
              onClick={() => setShowModules((s) => !s)}
              aria-pressed={showModules}
              className="px-2.5 py-1.5 text-xs rounded-lg border transition-colors"
              style={{ borderColor: 'var(--border)', color: 'var(--muted)', background: showModules ? 'var(--panel)' : 'transparent' }}
            >
              {showModules ? t('pivot.hideModules') : t('pivot.showModules', { count: moduleIds.size })}
            </button>
          )}
          {data && data.nodes.length > 0 && <ExportCsvButton onExport={onExport} label={t('pivot.export')} />}
        </div>
      </div>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div className="w-6 h-6 rounded-full border-2 animate-spin"
               style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }} aria-label={t('pivot.loading')} />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>{t('pivot.loading')}</span>
        </div>
      )}
      {error && (
        <div className="rounded-xl border p-4 flex items-center gap-3"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }} role="alert">
          <AlertTriangle size={16} aria-hidden /> {error}
        </div>
      )}

      {data && !error && (data.summary.nodes_truncated || data.summary.edges_truncated) && (
        <div className="text-xs rounded-lg border px-3 py-2 space-y-0.5"
             style={{ borderColor: 'var(--border)', color: 'var(--muted)', background: 'var(--panel)' }}>
          {data.summary.nodes_truncated && (
            <div>{t('pivot.truncated', { shown: data.summary.node_count, total: data.summary.nodes_total })}</div>
          )}
          {data.summary.edges_truncated && (
            <div>{t('pivot.edgesTruncated', { shown: data.summary.edge_count, total: data.summary.edges_total })}</div>
          )}
        </div>
      )}

      {data && !error && (
        <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)', height: 560 }}>
          <ErrorBoundary key={`${detection}:${hops}:${showModules}`}>
            <Suspense fallback={<div className="w-full h-full flex items-center justify-center"><span className="text-sm" style={{ color: 'var(--muted)' }}>{t('pivot.loading')}</span></div>}>
              <CytoscapeComponent
                elements={shownElements as never}
                stylesheet={STYLESHEET as never}
                layout={cyLayout as never}
                style={{ width: '100%', height: '100%' }}
                cy={(cy: CyCore) => {
                  cy.on('tap', 'node', (evt) => {
                    setElements((els) => revealNeighbors(els, evt.target.id()));
                  });
                  // Hover focus: dim everything except the hovered node's neighborhood, reveal its edge labels.
                  cy.on('mouseover', 'node', (evt) => {
                    const n = evt.target;
                    cy.batch(() => {
                      cy.elements().addClass('faded');
                      n.closedNeighborhood().removeClass('faded');
                      n.connectedEdges().addClass('elabel');
                    });
                  });
                  cy.on('mouseout', 'node', () => {
                    cy.batch(() => { cy.elements().removeClass('faded'); cy.edges().removeClass('elabel'); });
                  });
                }}
              />
            </Suspense>
          </ErrorBoundary>
        </div>
      )}

      {/* Legend */}
      {data && !error && (
        <div className="text-xs flex flex-wrap items-center gap-x-4 gap-y-2" style={{ color: 'var(--muted)' }}>
          <span className="font-semibold">{t('pivot.legend')}:</span>
          <span>{t('pivot.fillCrit')}</span>
          <span className="flex items-center gap-1.5">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const).map((c) => (
              <span key={c} className="inline-flex items-center gap-1">
                <span style={{ width: 14, height: 10, borderRadius: 3, background: CRIT_STYLE[c].bg, border: '1px solid #30363d', display: 'inline-block' }} />
                {c}
              </span>
            ))}
          </span>
          <span className="inline-flex items-center gap-1">
            <span style={{ width: 14, height: 10, borderRadius: 3, background: 'transparent', border: '2px solid #58a6ff', display: 'inline-block' }} />
            {t('pivot.seedNode')}
          </span>
          <span className="inline-flex items-center gap-2">
            <span className="inline-flex items-center gap-1"><span style={{ width: 16, height: 0, borderTop: '2px solid #539bf5', display: 'inline-block' }} />{t('pivot.spawned')}</span>
            <span className="inline-flex items-center gap-1"><span style={{ width: 16, height: 0, borderTop: '2px dashed #bc8cff', display: 'inline-block' }} />{t('pivot.exhibited')}</span>
            <span className="inline-flex items-center gap-1"><span style={{ width: 16, height: 0, borderTop: '2px dotted #6e7681', display: 'inline-block' }} />{t('pivot.runsOn')}</span>
          </span>
        </div>
      )}

      {/* Honesty panel */}
      {data && !error && (
        <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{data.summary.honesty_note}</p>
      )}
    </div>
  );
}
