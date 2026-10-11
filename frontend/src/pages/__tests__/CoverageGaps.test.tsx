import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import CoverageGaps from '../CoverageGaps';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';
import * as csv from '../../lib/csv';

const server = setupServer();

const RESP = {
  tactics: [
    { id: 'TA0001', name: 'Initial Access' },
    { id: 'TA0002', name: 'Execution' },
  ],
  os_families: ['windows', 'linux', 'macos'],
  cells: {
    TA0001: {
      windows: { covered: true, count: 2 },
      linux: { covered: false, count: 0 },
      macos: { covered: false, count: 0 },
    },
    TA0002: {
      windows: { covered: true, count: 1 },
      linux: { covered: true, count: 1 },
      macos: { covered: false, count: 0 },
    },
  },
  summary: {
    os_families: ['windows', 'linux', 'macos'],
    total_cells: 6,
    covered_cells: 4,
    gap_cells: 2,
    coverage_pct: 0.6667,
  },
};

beforeEach(() => {
  server.listen({ onUnhandledFrame: 'error' });
  useAuthStore.setState({ user: 'alice', role: 'viewer', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
});
afterEach(() => {
  server.resetHandlers();
  server.close();
});

function setup() {
  return render(
    <MemoryRouter>
      <CoverageGaps />
    </MemoryRouter>
  );
}

describe('CoverageGaps page', () => {
  it('renders tactic rows and OS columns', async () => {
    server.use(http.get('/api/coverage_gaps', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText('Initial Access')).toBeInTheDocument());
    expect(screen.getByText('Execution')).toBeInTheDocument();
    expect(screen.getAllByText(/windows/i).length).toBeGreaterThan(0);
  });

  it('renders a covered cell count and a gap cell', async () => {
    server.use(http.get('/api/coverage_gaps', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText('Initial Access')).toBeInTheDocument());
    expect(screen.getByText('2')).toBeInTheDocument(); // windows count for TA0001
    expect(screen.getAllByText('—').length).toBeGreaterThan(0); // gap cells
  });

  it('covered cells link to /drill to prove coverage', async () => {
    server.use(http.get('/api/coverage_gaps', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText('Initial Access')).toBeInTheDocument());
    const links = screen.getAllByRole('link', { name: /prove this scenario/i });
    expect(links.length).toBeGreaterThan(0);
    links.forEach((l) => expect(l).toHaveAttribute('href', '/drill'));
  });

  it('renders the summary line', async () => {
    server.use(http.get('/api/coverage_gaps', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText(/4 of 6 cells covered/i)).toBeInTheDocument());
  });

  it('renders the binding cloud-stub legend (AUDIT #2)', async () => {
    server.use(http.get('/api/coverage_gaps', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText(/no Cloud column/i)).toBeInTheDocument());
  });

  it('Export ATT&CK Layer fetches type=coverage and downloads json', async () => {
    let capturedUrl = '';
    server.use(
      http.get('/api/coverage_gaps', () => HttpResponse.json(RESP)),
      http.get('/api/navigator_layer', ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json({ name: 'Augur — Coverage', techniques: [] });
      })
    );
    const spy = vi.spyOn(csv, 'downloadJson').mockImplementation(() => {});
    setup();
    await waitFor(() => expect(screen.getByText('Initial Access')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /export att&ck layer/i }));
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1));
    expect(capturedUrl).toContain('type=coverage');
    expect(spy.mock.calls[0][0]).toMatch(/^augur-attack-coverage-\d{4}-\d{2}-\d{2}\.json$/);
    spy.mockRestore();
  });

  it('shows loading initially', () => {
    server.use(
      http.get('/api/coverage_gaps', async () => {
        await new Promise((r) => setTimeout(r, 2000));
        return HttpResponse.json(RESP);
      })
    );
    setup();
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('shows empty state when no os families', async () => {
    server.use(
      http.get('/api/coverage_gaps', () =>
        HttpResponse.json({
          tactics: [],
          os_families: [],
          cells: {},
          summary: { os_families: [], total_cells: 0, covered_cells: 0, gap_cells: 0, coverage_pct: 0 },
        })
      )
    );
    setup();
    await waitFor(() => expect(screen.getByText(/no coverage data/i)).toBeInTheDocument());
  });

  it('shows error state on failure', async () => {
    server.use(http.get('/api/coverage_gaps', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    setup();
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
  });
});
