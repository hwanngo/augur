import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Drill from '../Drill';
import { configureApi } from '../../lib/api';

const scenarios = [
  { scenario_id: 'SCEN-WIN-001', name: 'LSASS dump', severity: 'CRITICAL', steps: 4,
    os_family: 'windows', applicable_zones: ['User_Endpoint', 'Internal_Server'], synthesizable: true,
    mitre: [{ tactic: 'TA0006', technique: 'T1003' }] },
  { scenario_id: 'SCEN-REAL-WIN-T1548-002-001', name: 'UAC bypass', severity: 'HIGH', steps: 3,
    os_family: 'windows', applicable_zones: ['User_Endpoint'], synthesizable: false,
    mitre: [{ tactic: 'TA0004', technique: 'T1548' }] },
];
const topology = { zones: ['User_Endpoint', 'DMZ'], assets: [
  { hostname: 'HR_User_PC', os: 'Windows 11', zone: 'User_Endpoint', criticality: 'MEDIUM', ip: '10.0.0.1', role: null },
  { hostname: 'Reverse_Proxy_01', os: 'Linux', zone: 'DMZ', criticality: 'HIGH', ip: '10.0.0.2', role: null },
] };
const drillResult = {
  scenario_id: 'SCEN-WIN-001', host: 'HR_User_PC', mode: 'inject',
  note: 'Synth-injected onto the target host.',
  detection: { scenario_id: 'SCEN-WIN-001', name: 'LSASS dump', severity: 'CRITICAL', proximity: 1,
    matched_steps: [], missing_steps: [], affected_hosts: ['HR_User_PC'],
    affected_zones: ['User_Endpoint'], hunting_queries: [] },
  feed_summary: { total_events: 724, baseline_events: 720, injected_events: 4 },
};
const replayResult = {
  scenario_id: 'SCEN-REAL-WIN-T1548-002-001', host: null, mode: 'replay',
  note: 'Replayed against loaded real telemetry — not synthesized.',
  replay_hosts: ['WORKSTATION5.theshire.local'],
  detection: { scenario_id: 'SCEN-REAL-WIN-T1548-002-001', name: 'UAC bypass', severity: 'HIGH',
    proximity: 1, matched_steps: [], missing_steps: [], affected_hosts: ['WORKSTATION5.theshire.local'],
    affected_zones: ['User_Endpoint'], hunting_queries: [] },
  feed_summary: null,
};

const server = setupServer(
  http.get('/api/scenarios', () => HttpResponse.json(scenarios)),
  http.get('/api/topology', () => HttpResponse.json(topology)),
  http.post('/api/drill', () => HttpResponse.json(drillResult)),
);
beforeAll(() => { server.listen(); configureApi({ onUnauthorized() {}, getCsrf: () => 'tok' }); });
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function setup(entry = '/drill') {
  return render(<MemoryRouter initialEntries={[entry]}><Drill /></MemoryRouter>);
}

async function selectScenario() {
  const scenTrigger = await screen.findByRole('combobox', { name: /scenario/i });
  fireEvent.click(scenTrigger);
  fireEvent.click(await screen.findByRole('option', { name: /SCEN-WIN-001/i }));
}

describe('Drill page', () => {
  it('filters host options to matching os_family AND zone ∈ applicable_zones', async () => {
    setup();
    await selectScenario();
    const hostTrigger = await screen.findByRole('combobox', { name: /target host/i });
    // Open the host dropdown to check its options
    fireEvent.click(hostTrigger);
    await waitFor(() => expect(screen.getByRole('option', { name: 'HR_User_PC' })).toBeInTheDocument());
    // Reverse_Proxy_01 is linux + DMZ → excluded
    expect(screen.queryByRole('option', { name: 'Reverse_Proxy_01' })).not.toBeInTheDocument();
    // Close dropdown
    fireEvent.keyDown(hostTrigger, { key: 'Escape' });
  });

  it('runs a drill and shows the detection banner + feed summary', async () => {
    setup();
    await selectScenario();
    const hostTrigger = await screen.findByRole('combobox', { name: /target host/i });
    fireEvent.click(hostTrigger);
    await waitFor(() => expect(screen.getByRole('option', { name: 'HR_User_PC' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('option', { name: 'HR_User_PC' }));
    fireEvent.click(screen.getByRole('button', { name: /run drill/i }));
    expect(await screen.findByText(/detected at 100%/i)).toBeInTheDocument();
    expect(screen.getByText('LSASS dump')).toBeInTheDocument();
    expect(screen.getByText(/724 events/)).toBeInTheDocument();
  });

  it('preselects the scenario from ?scenario_id=', async () => {
    setup('/drill?scenario_id=SCEN-WIN-001');
    const scenTrigger = await screen.findByRole('combobox', { name: /scenario/i });
    await waitFor(() => expect(scenTrigger).toHaveTextContent('SCEN-WIN-001'));
  });

  it('shows a 422 error message on failure', async () => {
    server.use(http.post('/api/drill', () =>
      HttpResponse.json({ detail: 'host X (zone DMZ) is not in applicable_zones' }, { status: 422 })));
    setup();
    await selectScenario();
    const hostTrigger = await screen.findByRole('combobox', { name: /target host/i });
    fireEvent.click(hostTrigger);
    await waitFor(() => expect(screen.getByRole('option', { name: 'HR_User_PC' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('option', { name: 'HR_User_PC' }));
    fireEvent.click(screen.getByRole('button', { name: /run drill/i }));
    expect(await screen.findByText(/not in applicable_zones/i)).toBeInTheDocument();
  });

  async function selectRealScenario() {
    const scenTrigger = await screen.findByRole('combobox', { name: /scenario/i });
    fireEvent.click(scenTrigger);
    fireEvent.click(await screen.findByRole('option', { name: /SCEN-REAL-WIN-T1548-002-001/i }));
  }

  it('hides the host picker and shows a Replay button for a non-synthesizable scenario', async () => {
    setup();
    await selectRealScenario();
    // Host picker is hidden for replay (the capture decides the host, not the user).
    expect(screen.queryByRole('combobox', { name: /target host/i })).not.toBeInTheDocument();
    // Button is relabelled "Replay" and is enabled without a host selection.
    const btn = await screen.findByRole('button', { name: /^replay$/i });
    expect(btn).not.toBeDisabled();
  });

  it('runs a replay and shows the honest note + matched host (no feed summary)', async () => {
    server.use(http.post('/api/drill', () => HttpResponse.json(replayResult)));
    setup();
    await selectRealScenario();
    fireEvent.click(await screen.findByRole('button', { name: /^replay$/i }));
    expect(await screen.findByText(/detected at 100%/i)).toBeInTheDocument();
    expect(screen.getByText('UAC bypass')).toBeInTheDocument();
    expect(screen.getByText(/replayed against loaded real telemetry/i)).toBeInTheDocument();
    // Host appears in both the detection card and the "matched on" line.
    expect(screen.getAllByText(/WORKSTATION5\.theshire\.local/).length).toBeGreaterThan(0);
    // No synth feed-summary line for replay.
    expect(screen.queryByText(/baseline/i)).not.toBeInTheDocument();
  });
});
