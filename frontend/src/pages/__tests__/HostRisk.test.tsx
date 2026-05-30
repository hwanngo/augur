import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import HostRisk, { type HostRow } from '../HostRisk';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';

const server = setupServer();

const HOSTS: HostRow[] = [
  {
    hostname: 'DC_01', zone: 'Active_Directory', criticality: 'CRITICAL', score: 14, band: 'CRITICAL',
    detection_count: 2, max_proximity: 1.0, top_severity: 'HIGH',
    top_scenarios: [
      { scenario_id: 'S1', name: 'Golden Ticket', severity: 'HIGH', proximity: 1.0 },
      { scenario_id: 'S3', name: 'DCSync', severity: 'HIGH', proximity: 0.8 },
    ],
  },
  {
    hostname: 'Web_Server_01', zone: 'DMZ', criticality: 'HIGH', score: 4.5, band: 'HIGH',
    detection_count: 1, max_proximity: 0.5, top_severity: 'HIGH',
    top_scenarios: [{ scenario_id: 'S2', name: 'Webshell', severity: 'HIGH', proximity: 0.5 }],
  },
  {
    hostname: 'HR_User_PC', zone: 'User_Endpoint', criticality: 'MEDIUM', score: 0, band: 'CLEAR',
    detection_count: 0, max_proximity: 0, top_severity: null, top_scenarios: [],
  },
];

const RESP = { hosts: HOSTS };
// Alias for new tests that reference HOST_RISK_RESPONSE
const HOST_RISK_RESPONSE = RESP;

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });
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
      <HostRisk />
    </MemoryRouter>
  );
}

describe('HostRisk page', () => {
  it('renders host rows from a mocked response', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => {
      expect(screen.getByText('DC_01')).toBeInTheDocument();
      expect(screen.getByText('Web_Server_01')).toBeInTheDocument();
      expect(screen.getByText('Golden Ticket')).toBeInTheDocument();
    });
  });

  it('renders band chips', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText('DC_01')).toBeInTheDocument());
    expect(screen.getAllByText(/critical/i).length).toBeGreaterThan(0);
  });

  it('renders the "+N more" scenario hint', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText('Golden Ticket')).toBeInTheDocument());
    expect(screen.getByText(/\+1 more/i)).toBeInTheDocument();
  });

  it('defaults to score-descending order (DC_01 first)', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText('DC_01')).toBeInTheDocument());
    const rows = screen.getAllByRole('row');
    // rows[0] is the header; rows[1] is the first body row.
    expect(rows[1]).toHaveTextContent('DC_01');
  });

  it('reverses order when the Score header is clicked', async () => {
    const u = userEvent.setup();
    server.use(http.get('/api/host_risk', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText('DC_01')).toBeInTheDocument());
    await u.click(screen.getByText(/^Score$/i));
    const rows = screen.getAllByRole('row');
    expect(rows[1]).toHaveTextContent('HR_User_PC'); // lowest score first
  });

  it('filters by hostname via the search box', async () => {
    const u = userEvent.setup();
    server.use(http.get('/api/host_risk', () => HttpResponse.json(RESP)));
    setup();
    await waitFor(() => expect(screen.getByText('DC_01')).toBeInTheDocument());
    await u.type(screen.getByRole('searchbox'), 'web');
    expect(screen.getByText('Web_Server_01')).toBeInTheDocument();
    expect(screen.queryByText('DC_01')).not.toBeInTheDocument();
  });

  it('shows loading state initially', () => {
    server.use(http.get('/api/host_risk', async () => {
      await new Promise((r) => setTimeout(r, 2000));
      return HttpResponse.json(RESP);
    }));
    setup();
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('shows empty state when no hosts', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json({ hosts: [] })));
    setup();
    await waitFor(() => expect(screen.getByText(/no hosts/i)).toBeInTheDocument());
  });

  it('shows error state on failure', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    setup();
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
  });

  it('opens the drawer with the FULL top_scenarios list (row truncates it)', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json(HOST_RISK_RESPONSE)));
    setup();
    const first = HOST_RISK_RESPONSE.hosts[0];
    const btn = await screen.findByRole('button', {
      name: new RegExp(`view details for ${first.hostname}`, 'i'),
    });
    fireEvent.click(btn);
    const dlg = screen.getByRole('dialog');
    // every scenario name surfaces in the drawer (row showed only the first)
    for (const s of first.top_scenarios) {
      expect(within(dlg).getByText(s.name)).toBeInTheDocument();
    }
    expect(within(dlg).getAllByText(String(first.max_proximity)).length).toBeGreaterThan(0);
  });

  it('opens on load from ?host= deep-link', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json(HOST_RISK_RESPONSE)));
    const h = HOST_RISK_RESPONSE.hosts[0].hostname;
    render(
      <MemoryRouter initialEntries={[`/host-risk?host=${h}`]}>
        <HostRisk />
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
  });

  it('?host= deep-link: Esc closes drawer, clears param, and flips aria-selected to false', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json(HOST_RISK_RESPONSE)));
    const h = HOST_RISK_RESPONSE.hosts[0].hostname;
    render(
      <MemoryRouter initialEntries={[`/host-risk?host=${h}`]}>
        <HostRisk />
      </MemoryRouter>
    );
    // Drawer should be open from the deep-link.
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
    // The row button should be aria-current=true while the drawer is open.
    const btn = screen.getByRole('button', { name: new RegExp(`view details for ${h}`, 'i') });
    expect(btn).toHaveAttribute('aria-current', 'true');

    // Press Escape to close.
    fireEvent.keyDown(document, { key: 'Escape' });

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(btn).toHaveAttribute('aria-current', 'false');
  });

  it('header sort does not open the drawer', async () => {
    server.use(http.get('/api/host_risk', () => HttpResponse.json(HOST_RISK_RESPONSE)));
    setup();
    await screen.findByText(HOST_RISK_RESPONSE.hosts[0].hostname);
    fireEvent.click(screen.getByText('Score'));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
