import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import CandidatesPage, { type Candidate } from '../Candidates';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';
import Toaster from '../../components/Toaster';
import { useToastStore } from '../../store/toast';

const server = setupServer();

const CANDIDATES: Candidate[] = [
  {
    id: 'a1', scenario_id: 'SCEN-GEN-0001', category: 'credential_access', status: 'pending',
    plausibility: 0.9, seed_id: 'SCEN-2026-001', mutation_axes: 'lolbin', created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z', reviewed_by: '', reviewed_at: '',
    yaml: 'scenario_metadata:\n  scenario_id: SCEN-GEN-0001\n', gauntlet_report: '{"notes":["looks good"]}',
  },
  {
    id: 'b2', scenario_id: 'SCEN-GEN-0002', category: 'execution', status: 'approved',
    plausibility: 0.7, seed_id: 'SCEN-2026-009', mutation_axes: '', created_by: 'admin',
    created_at: '2026-01-02T00:00:00Z', reviewed_by: 'admin', reviewed_at: '2026-01-03T00:00:00Z',
    yaml: 'scenario_metadata:\n  scenario_id: SCEN-GEN-0002\n', gauntlet_report: '{"notes":[]}',
  },
];

beforeEach(() => {
  server.listen({ onUnhandledFrame: 'error' });
  useAuthStore.setState({ user: 'admin', role: 'admin', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
  act(() => useToastStore.setState({ show: false, message: '', status: 'success' }));
});
afterEach(() => {
  server.resetHandlers();
  server.close();
  act(() => useToastStore.setState({ show: false, message: '', status: 'success' }));
});

function setup() {
  return render(
    <MemoryRouter>
      <CandidatesPage />
      <Toaster />
    </MemoryRouter>
  );
}

describe('Candidates page', () => {
  it('renders the candidate rows', async () => {
    server.use(http.get('/api/candidates', () => HttpResponse.json(CANDIDATES)));
    setup();
    await waitFor(() => {
      expect(screen.getByText('SCEN-GEN-0001')).toBeInTheDocument();
      expect(screen.getByText('SCEN-GEN-0002')).toBeInTheDocument();
    });
  });

  it('filters to pending only', async () => {
    server.use(http.get('/api/candidates', () => HttpResponse.json(CANDIDATES)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-GEN-0002')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('tab', { name: /pending/i }));
    expect(screen.getByText('SCEN-GEN-0001')).toBeInTheDocument();
    expect(screen.queryByText('SCEN-GEN-0002')).not.toBeInTheDocument();
  });

  it('opens detail dialog with YAML and approve action for a pending candidate', async () => {
    server.use(http.get('/api/candidates', () => HttpResponse.json(CANDIDATES)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-GEN-0001')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /view candidate scen-gen-0001/i }));
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.getByText('looks good')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument();
    });
  });

  it('approves a candidate and refreshes', async () => {
    let approved = false;
    server.use(
      http.get('/api/candidates', () =>
        HttpResponse.json(approved ? [{ ...CANDIDATES[0], status: 'approved' as const }, CANDIDATES[1]] : CANDIDATES)
      ),
      http.post('/api/candidates/a1/approve', () => {
        approved = true;
        return HttpResponse.json({ status: 'approved', scenario_id: 'SCEN-GEN-0001', path: '/x.yaml' });
      })
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-GEN-0001')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /view candidate scen-gen-0001/i }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));

    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/approved/i));
  });

  it('opens the generate dialog', async () => {
    server.use(http.get('/api/candidates', () => HttpResponse.json([])));
    setup();
    await waitFor(() => expect(screen.getByText(/no candidates yet/i)).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Generate' }));
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.getByText('Generate Candidates')).toBeInTheDocument();
    });
  });
});
