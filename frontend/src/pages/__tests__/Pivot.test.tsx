import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Pivot, { revealNeighbors, moduleNodeIds, applyModuleHidden } from '../Pivot';
import * as api from '../../lib/api';

// Cytoscape renders to a canvas jsdom lacks — mock the wrapper and capture props.
// The component is lazy-loaded in Pivot.tsx (to keep cytoscape out of the static dep graph),
// so we mock at the module level; vi.mock is hoisted before imports by vitest.
let lastProps: any = null;
vi.mock('react-cytoscapejs', () => ({
  default: (props: any) => {
    lastProps = props;
    return <div data-testid="cy" data-elements={JSON.stringify(props.elements)} />;
  },
}));
// Lazy-loaded components use Suspense; we need act + async assertions.
// The mock above resolves synchronously so React.lazy settles immediately.

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k) }),
}));

const NOTE = 'Edges are host-local causal relationships — NOT network reachability …';
const PAYLOAD = {
  seed: { scenario_id: 'SCEN-WIN-001', name: 'Pass-the-Hash', severity: 'CRITICAL',
          seed_node_ids: ['p1'], affected_hosts: ['WS-FIN-07'] },
  nodes: [
    { id: 'p1', node_type: 'Process', label: 'evil.exe', host: 'WS-FIN-07',
      criticality: 'HIGH', zone: 'User_Endpoint', seed: true, hop: 0, name: 'evil.exe',
      command: 'evil', integrity_level: 'High' },
    { id: 'ws-fin-07', node_type: 'Host', label: 'WS-FIN-07', host: 'WS-FIN-07',
      criticality: 'HIGH', zone: 'User_Endpoint', seed: false, hop: 1 },
    { id: 'f1', node_type: 'File', label: 'x.dll', host: 'WS-FIN-07',
      criticality: 'HIGH', zone: 'User_Endpoint', seed: false, hop: 1, is_injected: true },
  ],
  edges: [
    { id: 'p1->ws-fin-07:RUNS_ON:t', src: 'p1', dst: 'ws-fin-07', edge_type: 'RUNS_ON', timestamp: 't' },
    { id: 'p1->f1:LOADED:t', src: 'p1', dst: 'f1', edge_type: 'LOADED', timestamp: 't', is_injected: true },
  ],
  summary: { node_count: 3, edge_count: 2, nodes_total: 3, edges_total: 2,
             nodes_truncated: false, edges_truncated: false, hops: 2, honesty_note: NOTE },
};

function renderAt(search = '?detection=SCEN-WIN-001') {
  return render(
    <MemoryRouter initialEntries={[`/pivot${search}`]}>
      <Pivot />
    </MemoryRouter>
  );
}

describe('Pivot', () => {
  beforeEach(() => { lastProps = null; vi.restoreAllMocks(); });

  it('passes mapped elements (nodes + edges) and a stylesheet to Cytoscape', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt();
    await waitFor(() => expect(screen.getByTestId('cy')).toBeInTheDocument());
    const els = lastProps.elements as any[];
    const nodes = els.filter((e) => !e.data.source);
    const edges = els.filter((e) => e.data.source);
    expect(nodes).toHaveLength(3);
    expect(edges).toHaveLength(2);
    // seed flag + criticality carried onto the node data
    const p1 = nodes.find((n) => n.data.id === 'p1');
    expect(p1.data.seed).toBe(true);
    expect(p1.data.criticality).toBe('HIGH');
    // edge labels by edge_type
    expect(edges.map((e) => e.data.label).sort()).toEqual(['LOADED', 'RUNS_ON']);
    // a stylesheet array is provided
    expect(Array.isArray(lastProps.stylesheet)).toBe(true);
  });

  it('renders the honesty note, legend, and hop selector chrome', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt();
    await waitFor(() => expect(screen.getByText(NOTE)).toBeInTheDocument());
    expect(screen.getByText(/pivot\.legend/)).toBeInTheDocument();
    expect(screen.getByLabelText('pivot.hops')).toBeInTheDocument();
  });

  it('shows the node truncation banner when nodes_truncated', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue({
      ...PAYLOAD,
      summary: { ...PAYLOAD.summary, nodes_truncated: true, node_count: 1, nodes_total: 99 },
    } as never);
    renderAt();
    await waitFor(() => expect(screen.getByText(/pivot.truncated/)).toBeInTheDocument());
    expect(screen.queryByText(/pivot.edgesTruncated/)).not.toBeInTheDocument();
  });

  it('shows the edge truncation banner when edges_truncated (and not nodes)', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue({
      ...PAYLOAD,
      summary: { ...PAYLOAD.summary, edges_truncated: true, edge_count: 1, edges_total: 50 },
    } as never);
    renderAt();
    await waitFor(() => expect(screen.getByText(/pivot.edgesTruncated/)).toBeInTheDocument());
    expect(screen.queryByText(/pivot\.truncated(?!.*edges)/)).not.toBeInTheDocument();
  });

  it('shows the detection picker when no detection is in the URL', async () => {
    const det = { scenario_id: 'SCEN-WIN-001', name: 'Pass-the-Hash', severity: 'CRITICAL',
      proximity: 1, matched_steps: [], missing_steps: [], affected_hosts: ['WS-FIN-07'],
      affected_zones: [], hunting_queries: [] };
    vi.spyOn(api, 'apiGet').mockResolvedValue([det] as never);
    renderAt('');
    expect(screen.getByText('pivot.pickPrompt')).toBeInTheDocument();
    // the picker lists the detection and links into the pivot
    await waitFor(() => expect(screen.getByText('Pass-the-Hash')).toBeInTheDocument());
    expect(screen.getByText(/SCEN-WIN-001 · 100%/)).toBeInTheDocument();
  });

  it('moduleNodeIds collects LOADED non-injected File nodes only', () => {
    // f1 in PAYLOAD is LOADED but is_injected → must stay visible (not a module).
    expect(moduleNodeIds(PAYLOAD as never).size).toBe(0);
    const withModule = {
      ...PAYLOAD,
      nodes: [...PAYLOAD.nodes, { id: 'dll1', node_type: 'File', label: 'kernel32.dll', host: 'WS-FIN-07',
        criticality: 'HIGH', zone: 'User_Endpoint', seed: false, hop: 1, is_injected: false }],
      edges: [...PAYLOAD.edges, { id: 'p1->dll1:LOADED:t', src: 'p1', dst: 'dll1', edge_type: 'LOADED', timestamp: 't' }],
    };
    const ids = moduleNodeIds(withModule as never);
    expect(ids.has('dll1')).toBe(true);
    expect(ids.has('f1')).toBe(false);
  });

  it('applyModuleHidden hides module nodes + touching edges when show=false, and clears them when show=true', () => {
    const els = [
      { data: { id: 'p1' } },
      { data: { id: 'dll1' }, classes: 'hidden' }, // a deep (hop>1) module also carries the depth class
      { data: { id: 'e', source: 'p1', target: 'dll1', label: 'LOADED' }, classes: 'hidden' },
    ];
    const ids = new Set(['dll1']);
    const hidden = applyModuleHidden(els, ids, false);
    expect((hidden.find((e) => e.data.id === 'dll1') as any).classes).toContain('module-hidden');
    expect((hidden.find((e) => e.data.id === 'e') as any).classes).toContain('module-hidden');
    expect((hidden.find((e) => e.data.id === 'p1') as any).classes ?? '').not.toContain('module-hidden');
    const shown = applyModuleHidden(hidden, ids, true);
    // show clears BOTH module-hidden and the depth `hidden` so modules reveal regardless of hop
    expect((shown.find((e) => e.data.id === 'dll1') as any).classes ?? '').not.toMatch(/module-hidden|hidden/);
    expect((shown.find((e) => e.data.id === 'e') as any).classes ?? '').not.toMatch(/module-hidden|hidden/);
  });

  it('revealNeighbors un-hides the tapped node\'s direct neighbors', () => {
    // hidden deeper elements get { classes: 'hidden' }; revealing 'p1' un-hides p1's edges + their other endpoint
    const els = [
      { data: { id: 'p1' } },
      { data: { id: 'p2' }, classes: 'hidden' },
      { data: { id: 'e1', source: 'p1', target: 'p2', label: 'SPAWNED' }, classes: 'hidden' },
    ];
    const next = revealNeighbors(els, 'p1');
    const p2 = next.find((e) => e.data.id === 'p2');
    const e1 = next.find((e) => e.data.id === 'e1');
    expect((p2 as any).classes ?? '').not.toContain('hidden');
    expect((e1 as any).classes ?? '').not.toContain('hidden');
  });
});
