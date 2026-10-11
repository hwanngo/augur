import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Hunts, { type Hunt, type HuntDetail } from '../Hunts';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';

const server = setupServer();

const HUNTS: Hunt[] = [
  {
    id: 'h1', owner: 'an', hypothesis: 'Lateral movement from DMZ into user endpoints',
    scope: { zone: 'DMZ' }, status: 'investigating', verdict_note: '', notes: '',
    verdict_evidence_at: null, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
  },
];

const DETAIL: HuntDetail = {
  ...HUNTS[0],
  honesty_note: 'Evidence is a deterministic engine run over in-scope logs; absence is not proof.',
  scope_resolved: { zone: 'DMZ' },
  verdict_evidence: null,
  evidence: [
    {
      scenario_id: 'SCEN-WIN-001', name: 'Cred Theft', severity: 'CRITICAL',
      proximity: 0.6667, matched_count: 2, total_steps: 3,
      matched_steps: [{ step_id: 1, name: 'DLL Inject' }],
      next_step_to_hunt: {
        step_id: 3, name: 'LSASS access',
        matching_criteria: { ProcessName: { in: ['rundll32.exe'] } },
        temporal: { previous_step: 2, link_scope: 'same_host', min_time_delta_seconds: 0, max_time_delta_seconds: 120 },
      },
      stall: null, hunting_queries: [], affected_hosts: ['HR_PC'], affected_zones: ['DMZ'],
    },
  ],
  events: [{ ts: '2026-01-01T00:00:00Z', actor: 'an', event: 'opened', detail: '' }],
};

beforeEach(() => {
  server.listen({ onUnhandledFrame: 'error' });
  server.use(
    http.get('/api/scenarios', () => HttpResponse.json([])),
    http.get('/api/topology', () => HttpResponse.json({ zones: ['DMZ'], assets: [{ hostname: 'HR_PC', os: 'Windows', zone: 'DMZ' }] })),
  );
  useAuthStore.setState({ user: 'an', role: 'analyst', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
});
afterEach(() => { server.resetHandlers(); server.close(); });

function setup() {
  return render(<MemoryRouter initialEntries={['/hunts']}><Hunts /></MemoryRouter>);
}

describe('Hunts page', () => {
  it('renders a hunt row with hypothesis and a status chip', async () => {
    server.use(http.get('/api/hunts', () => HttpResponse.json(HUNTS)));
    setup();
    await waitFor(() => {
      expect(screen.getByText(/Lateral movement from DMZ/i)).toBeInTheDocument();
      // "Investigating" appears both as a status-filter option and the row chip.
      expect(screen.getAllByText('Investigating').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('shows the empty state when there are no hunts', async () => {
    server.use(http.get('/api/hunts', () => HttpResponse.json([])));
    setup();
    await waitFor(() => expect(screen.getByText(/No hunts yet/i)).toBeInTheDocument());
  });

  it('opens detail and renders live evidence proximity + honesty banner', async () => {
    server.use(
      http.get('/api/hunts', () => HttpResponse.json(HUNTS)),
      http.get('/api/hunts/h1', () => HttpResponse.json(DETAIL)),
    );
    setup();
    await waitFor(() => expect(screen.getByText(/Lateral movement from DMZ/i)).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view hunt h1/i }));
    await waitFor(() => {
      expect(screen.getByRole('region', { name: /hunt detail/i })).toBeInTheDocument();
      // honesty note rendered prominently
      expect(screen.getByText(/deterministic engine run/i)).toBeInTheDocument();
      // proximity rendered as 0.6667
      expect(screen.getByText('0.6667')).toBeInTheDocument();
      // next-step-to-hunt formatter reused
      expect(screen.getByText(/Next: LSASS access/i)).toBeInTheDocument();
    });
  });
});
