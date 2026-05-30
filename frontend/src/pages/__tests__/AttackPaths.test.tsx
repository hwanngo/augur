import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import AttackPaths, { toElements } from '../AttackPaths';
import * as api from '../../lib/api';

// Cytoscape renders to a canvas jsdom lacks — mock the lazy wrapper and capture props.
let lastProps: any = null;
vi.mock('react-cytoscapejs', () => ({
  default: (props: any) => {
    lastProps = props;
    return <div data-testid="cy" data-elements={JSON.stringify(props.elements)} />;
  },
}));
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k) }),
}));

const NOTE = 'Plausible technique progression over the scenario library + zone model — not a network-reachability or exploitability claim.';
const PAYLOAD = {
  from: 'x', to: 'y', honesty_note: NOTE,
  paths: [{
    entry: { zone: 'DMZ' },
    target: { hostname: 'DC01', zone: 'Active_Directory', criticality: 'CRITICAL' },
    realized_pct: 0.1538, mean_observed_proximity: 0.165, observed_stop_count: 1, total_stop_count: 2,
    max_severity: 'HIGH', honesty_note: NOTE,
    stops: [
      { zone: 'DMZ', scenario_id: 'S-DMZ', scenario_name: 'Web exploit', tactic: 'TA0001', severity: 'HIGH',
        status: 'observed', observed_proximity: 0.66, matched_steps: 2, total_steps: 3, host: 'WEB01' },
      { zone: 'Active_Directory', scenario_id: 'S-AD', scenario_name: 'DCSync', tactic: 'TA0006', severity: 'CRITICAL',
        status: 'hypothetical', observed_proximity: 0, matched_steps: 0, total_steps: 4, host: 'DC01' },
    ],
  }],
};

function renderAt(search = '') {
  return render(
    <MemoryRouter initialEntries={[`/attack_paths${search}`]}>
      <AttackPaths />
    </MemoryRouter>
  );
}

describe('AttackPaths', () => {
  beforeEach(() => { lastProps = null; vi.restoreAllMocks(); });

  it('defaults to graph view (no ?view): cytoscape canvas present, table list absent', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt();
    await waitFor(() => expect(screen.getByTestId('cy')).toBeInTheDocument());
    expect(screen.queryByText(/Web exploit/)).not.toBeInTheDocument();
  });

  it('?view=table renders the table list, no canvas', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt('?view=table');
    await waitFor(() => expect(screen.getByText(/Web exploit/)).toBeInTheDocument());
    expect(screen.getByText(/DCSync/)).toBeInTheDocument();
    expect(screen.queryByTestId('cy')).not.toBeInTheDocument();
  });

  it('toggle is a radiogroup with two radios; clicking Table switches view without refetch', async () => {
    const spy = vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt();
    await waitFor(() => expect(screen.getByTestId('cy')).toBeInTheDocument());
    const group = screen.getByRole('radiogroup');
    expect(group).toBeInTheDocument();
    const radios = screen.getAllByRole('radio');
    expect(radios).toHaveLength(2);
    fireEvent.click(screen.getByRole('radio', { name: /attackPaths\.view\.table/ }));
    await waitFor(() => expect(screen.getByText(/Web exploit/)).toBeInTheDocument());
    expect(screen.queryByTestId('cy')).not.toBeInTheDocument();
    expect(spy).toHaveBeenCalledTimes(1); // toggling never refetches
  });

  it('shows the empty state when there are no paths', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue({ ...PAYLOAD, paths: [] } as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('attackPaths.empty')).toBeInTheDocument());
  });

  it('graph view: passes mapped elements + a stylesheet to Cytoscape', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt();
    await waitFor(() => expect(screen.getByTestId('cy')).toBeInTheDocument());
    const els = lastProps.elements as any[];
    expect(els.filter((e: any) => !e.data.source)).toHaveLength(2); // 2 stops
    expect(els.filter((e: any) => e.data.source)).toHaveLength(1);  // 1 edge
    expect(Array.isArray(lastProps.stylesheet)).toBe(true);
    // amber observed rule + dashed hypothetical rule present
    const json = JSON.stringify(lastProps.stylesheet);
    expect(json).toContain('#F59E0B');
    expect(json).toContain('dashed');
    // breadthfirst, animation disabled (reduced-motion safe)
    expect(lastProps.layout.name).toBe('breadthfirst');
    expect(lastProps.layout.animate).toBe(false);
  });

  it('graph view: legend, honesty note, and per-lane summary render as real DOM', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt();
    await waitFor(() => expect(screen.getByTestId('cy')).toBeInTheDocument());
    expect(screen.getAllByText(/attackPaths\.legend/).length).toBeGreaterThan(0);
    expect(screen.getByText(NOTE)).toBeInTheDocument();                 // honesty in graph view
    // per-lane summary: target hostname + realized% as real DOM near the canvas
    expect(screen.getByText('DC01')).toBeInTheDocument();
    expect(screen.getByText(/attackPaths\.realized/)).toBeInTheDocument();
    // canvas wrapper is role=img with an aria summary
    const img = screen.getByRole('img', { name: /attackPaths\.graphAria/ });
    expect(img).toBeInTheDocument();
  });

  it('table view also shows the honesty note', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt('?view=table');
    await waitFor(() => expect(screen.getByText(/Web exploit/)).toBeInTheDocument());
    expect(screen.getByText(NOTE)).toBeInTheDocument();
  });

  it('keyboard: ArrowRight on Graph radio selects Table; ArrowLeft returns to Graph (directional)', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt(); // default: graph view
    await waitFor(() => expect(screen.getByTestId('cy')).toBeInTheDocument());

    const graphRadio = screen.getByRole('radio', { name: /attackPaths\.view\.graph/ });
    const tableRadio = screen.getByRole('radio', { name: /attackPaths\.view\.table/ });

    // Active radio should have tabIndex=0, inactive should have tabIndex=-1
    expect(graphRadio).toHaveAttribute('tabindex', '0');
    expect(tableRadio).toHaveAttribute('tabindex', '-1');

    // ArrowRight on Graph → Table becomes selected
    graphRadio.focus();
    fireEvent.keyDown(graphRadio, { key: 'ArrowRight' });
    await waitFor(() => expect(tableRadio).toHaveAttribute('aria-checked', 'true'));
    expect(graphRadio).toHaveAttribute('aria-checked', 'false');
    // Table is now active so tabIndex flips
    expect(tableRadio).toHaveAttribute('tabindex', '0');
    expect(graphRadio).toHaveAttribute('tabindex', '-1');

    // ArrowLeft on Table → Graph restored
    fireEvent.keyDown(tableRadio, { key: 'ArrowLeft' });
    await waitFor(() => expect(graphRadio).toHaveAttribute('aria-checked', 'true'));
    expect(tableRadio).toHaveAttribute('aria-checked', 'false');
  });
});

describe('toElements', () => {
  const twoLane = {
    from: 'x', to: 'y', honesty_note: 'n',
    paths: [
      // lane 0: observed → hypothetical (target)
      { entry: { zone: 'DMZ' }, target: { hostname: 'DC01', zone: 'Active_Directory', criticality: 'CRITICAL' },
        realized_pct: 0.5, mean_observed_proximity: 0.3, observed_stop_count: 1, total_stop_count: 2,
        max_severity: 'HIGH', honesty_note: 'n',
        stops: [
          { zone: 'DMZ', scenario_id: 'S1', scenario_name: 'a', tactic: 'TA0001', severity: 'HIGH',
            status: 'observed', observed_proximity: 0.6, matched_steps: 2, total_steps: 4, host: 'WEB01' },
          { zone: 'Active_Directory', scenario_id: 'S2', scenario_name: 'b', tactic: 'TA0006', severity: 'CRITICAL',
            status: 'hypothetical', observed_proximity: 0, matched_steps: 0, total_steps: 4, host: 'DC01' },
        ] },
      // lane 1: all observed, 3 stops (target)
      { entry: { zone: 'DMZ' }, target: { hostname: 'APP01', zone: 'Cloud_SaaS', criticality: 'CRITICAL' },
        realized_pct: 1.0, mean_observed_proximity: 0.8, observed_stop_count: 3, total_stop_count: 3,
        max_severity: 'CRITICAL', honesty_note: 'n',
        stops: [
          { zone: 'DMZ', scenario_id: 'S3', scenario_name: 'c', tactic: 'TA0001', severity: 'HIGH',
            status: 'observed', observed_proximity: 0.7, matched_steps: 1, total_steps: 1, host: 'WEB01' },
          { zone: 'User_Endpoint', scenario_id: 'S4', scenario_name: 'd', tactic: 'TA0002', severity: 'HIGH',
            status: 'observed', observed_proximity: 0.7, matched_steps: 1, total_steps: 1, host: 'WS01' },
          { zone: 'Cloud_SaaS', scenario_id: 'S5', scenario_name: 'e', tactic: 'TA0010', severity: 'CRITICAL',
            status: 'observed', observed_proximity: 0.9, matched_steps: 1, total_steps: 1, host: 'APP01' },
        ] },
    ],
  };

  it('maps lanes to lane-scoped nodes + edges with correct counts', () => {
    const els = toElements(twoLane as never);
    const nodes = els.filter((e) => !e.data.source);
    const edges = els.filter((e) => e.data.source);
    expect(nodes).toHaveLength(5);                 // 2 + 3 stops
    expect(edges).toHaveLength(3);                 // (2-1) + (3-1)
    // ids are lane-scoped + unique
    expect(new Set(els.map((e) => e.data.id)).size).toBe(els.length);
    expect(nodes.map((n) => n.data.id)).toContain('L0|S0');
    expect(edges.map((e) => e.data.id)).toContain('L1|E1');
  });

  it('flags the last stop of each lane as the target with criticality', () => {
    const els = toElements(twoLane as never);
    const t0 = els.find((e) => e.data.id === 'L0|S1')!;
    expect(t0.data.is_target).toBe(true);
    expect(t0.data.node_type).toBe('target');
    expect(t0.data.criticality).toBe('CRITICAL');
    const s0 = els.find((e) => e.data.id === 'L0|S0')!;
    expect(s0.data.is_target).toBe(false);
    expect(s0.data.node_type).toBe('stop');
    expect(s0.data.criticality).toBeNull();
  });

  it('edges carry the downstream stop status (amber vs hypothetical) + tactic label', () => {
    const els = toElements(twoLane as never);
    const e0 = els.find((e) => e.data.id === 'L0|E0')!;   // DMZ→AD, downstream = hypothetical
    expect(e0.data.status).toBe('hypothetical');
    expect(e0.data.label).toBe('TA0006');
    const e1 = els.find((e) => e.data.id === 'L1|E0')!;   // observed downstream
    expect(e1.data.status).toBe('observed');
    expect(e1.data.label).toBe('TA0002');
  });

  it('multi-lane: no edge crosses lane boundaries (honesty invariant)', () => {
    const els = toElements(twoLane as never);
    const edges = els.filter((e) => e.data.source);
    // Build a map from node id → lane
    const nodeLane = new Map<string, number>();
    els.filter((e) => !e.data.source).forEach((n) => {
      nodeLane.set(n.data.id as string, n.data.lane as number);
    });
    for (const edge of edges) {
      const srcLane = nodeLane.get(edge.data.source as string);
      const tgtLane = nodeLane.get(edge.data.target as string);
      expect(srcLane).toBeDefined();
      expect(tgtLane).toBeDefined();
      expect(srcLane).toBe(tgtLane); // no cross-lane edge
      // Also check edge.data.lane matches
      expect(edge.data.lane).toBe(srcLane);
    }
  });
});
