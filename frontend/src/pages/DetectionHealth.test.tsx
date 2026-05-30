import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import DetectionHealth from './DetectionHealth';
import * as api from '../lib/api';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k),
  }),
}));

const RESP = {
  summary: {
    scenarios_total: 3,
    by_state: { FIRING: 1, PARTIAL: 1, SILENT: 0, NEVER: 1 },
    corpus_span: { from: '2026-01-01T10:00:00+00:00', to: '2026-01-01T12:00:00+00:00' },
    sweep_buckets: 6,
    honesty_note: 'Health is computed over THIS loaded corpus only.',
  },
  scenarios: [
    {
      scenario_id: 'SCEN-LNX-009', name: 'Never one', severity: 'LOW', os_family: 'linux',
      tactics: ['TA0002'], state: 'NEVER', max_proximity: 0.0, fire_count: 0,
      last_fired: null, affected_host_count: 0,
    },
    {
      scenario_id: 'SCEN-WIN-002', name: 'Partial one', severity: 'MEDIUM', os_family: 'windows',
      tactics: ['TA0003'], state: 'PARTIAL', max_proximity: 0.5, fire_count: 3,
      last_fired: '2026-01-01T11:00:00+00:00', affected_host_count: 1,
    },
    {
      scenario_id: 'SCEN-WIN-001', name: 'Firing one', severity: 'HIGH', os_family: 'windows',
      tactics: ['TA0001'], state: 'FIRING', max_proximity: 1.0, fire_count: 6,
      last_fired: '2026-01-01T11:30:00+00:00', affected_host_count: 2,
    },
  ],
};

const EMPTY_RESP = {
  summary: {
    scenarios_total: 0,
    by_state: { FIRING: 0, PARTIAL: 0, SILENT: 0, NEVER: 0 },
    corpus_span: { from: null, to: null },
    sweep_buckets: 6,
    honesty_note: 'Health is computed over THIS loaded corpus only.',
  },
  scenarios: [],
};

function renderPage() {
  return render(<MemoryRouter initialEntries={['/health']}><DetectionHealth /></MemoryRouter>);
}

describe('DetectionHealth page', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('loads on mount and renders the scenario rows', async () => {
    const spy = vi.spyOn(api, 'apiGet').mockResolvedValue(RESP as never);
    renderPage();
    await waitFor(() => expect(screen.getByText('SCEN-WIN-001')).toBeInTheDocument());
    expect(spy).toHaveBeenCalledWith('/api/detection_health');
    expect(screen.getByText('Firing one')).toBeInTheDocument();
    expect(screen.getByText('Partial one')).toBeInTheDocument();
    expect(screen.getByText('Never one')).toBeInTheDocument();
  });

  it('renders the persistent honesty panel', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(RESP as never);
    renderPage();
    await waitFor(() => expect(screen.getByText('detectionHealth.honesty')).toBeInTheDocument());
  });

  it('renders a state chip per state present', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(RESP as never);
    renderPage();
    // chip labels go through t('detectionHealth.states.<STATE>'); a label may legitimately
    // appear both in the summary strip and on a matching table row.
    await waitFor(() => expect(screen.getAllByText('detectionHealth.states.FIRING').length).toBeGreaterThan(0));
    expect(screen.getAllByText('detectionHealth.states.PARTIAL').length).toBeGreaterThan(0);
    expect(screen.getAllByText('detectionHealth.states.NEVER').length).toBeGreaterThan(0);
    // SILENT has no row in RESP, so it appears exactly once (summary strip only).
    expect(screen.getByText('detectionHealth.states.SILENT')).toBeInTheDocument();
  });

  it('empty corpus: shows the empty-span label', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(EMPTY_RESP as never);
    renderPage();
    await waitFor(() => expect(screen.getByText('detectionHealth.spanEmpty')).toBeInTheDocument());
  });

  it('row drill is keyboard-operable: Enter opens the DetailDrawer', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(RESP as never);
    renderPage();
    await waitFor(() => expect(screen.getByText('SCEN-WIN-001')).toBeInTheDocument());
    const row = screen.getByRole('button', { name: /detectionHealth\.inspectRow.*SCEN-WIN-001/ });
    row.focus();
    fireEvent.keyDown(row, { key: 'Enter' });
    await waitFor(() => expect(screen.getByText('detectionHealth.drawer.tactics')).toBeInTheDocument());
  });

  it('error state renders the failure message', async () => {
    vi.spyOn(api, 'apiGet').mockRejectedValue(new api.ApiError(500, 'boom'));
    renderPage();
    await waitFor(() => expect(screen.getByText('boom')).toBeInTheDocument());
  });
});
