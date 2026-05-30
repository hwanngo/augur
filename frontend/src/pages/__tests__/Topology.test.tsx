import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Topology, { toElements, type Asset } from '../Topology';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';

// Cytoscape renders to a canvas jsdom lacks — mock the lazy wrapper and capture props.
let lastCyProps: any = null;
vi.mock('react-cytoscapejs', () => ({
  default: (props: any) => { lastCyProps = props; return <div data-testid="cy" />; },
}));

const server = setupServer();

const ASSETS: Asset[] = [
  { hostname: 'dc01.corp', zone: 'corp', criticality: 'CRITICAL', os: 'Windows Server 2022', ip: '10.0.0.1', role: 'Domain Controller' },
  { hostname: 'ws01.corp', zone: 'corp', criticality: 'MEDIUM', os: 'Windows 11', ip: '10.0.0.50', role: 'Workstation' },
  { hostname: 'fw01.dmz', zone: 'dmz', criticality: 'HIGH', os: 'pfSense', ip: '192.168.1.1', role: 'Firewall' },
];

const TOPOLOGY_RESPONSE = { zones: ['corp', 'dmz'], assets: ASSETS };

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });
  useAuthStore.setState({ user: 'alice', role: 'analyst', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
});
afterEach(() => {
  server.resetHandlers();
  server.close();
});

// The table tests render the Table view (graph is the default); the graph has its own tests below.
function setup() {
  return render(
    <MemoryRouter initialEntries={['/?view=table']}>
      <Topology />
    </MemoryRouter>
  );
}

describe('Topology page', () => {
  it('renders assets from a mocked response', async () => {
    server.use(
      http.get('/api/topology', () => HttpResponse.json(TOPOLOGY_RESPONSE))
    );

    setup();

    await waitFor(() => {
      expect(screen.getByText('dc01.corp')).toBeInTheDocument();
      expect(screen.getByText('ws01.corp')).toBeInTheDocument();
      expect(screen.getByText('fw01.dmz')).toBeInTheDocument();
    });
  });

  it('renders criticality chips', async () => {
    server.use(
      http.get('/api/topology', () => HttpResponse.json(TOPOLOGY_RESPONSE))
    );

    setup();

    await waitFor(() => {
      expect(screen.getByText('CRITICAL')).toBeInTheDocument();
      expect(screen.getByText('HIGH')).toBeInTheDocument();
      expect(screen.getByText('MEDIUM')).toBeInTheDocument();
    });
  });

  it('shows loading state initially', () => {
    server.use(
      http.get('/api/topology', async () => {
        await new Promise((r) => setTimeout(r, 2000));
        return HttpResponse.json(TOPOLOGY_RESPONSE);
      })
    );

    setup();
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('shows empty state when no assets', async () => {
    server.use(
      http.get('/api/topology', () => HttpResponse.json({ zones: [], assets: [] }))
    );

    setup();

    await waitFor(() => {
      expect(screen.getByText(/no assets/i)).toBeInTheDocument();
    });
  });

  it('shows error state on failure', async () => {
    server.use(
      http.get('/api/topology', () => HttpResponse.json({ detail: 'Server error' }, { status: 500 }))
    );

    setup();

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });

  it('opens the detail drawer with the host full asset card on identity-button click', async () => {
    server.use(http.get('/api/topology', () => HttpResponse.json(TOPOLOGY_RESPONSE)));
    setup();
    const btn = await screen.findByRole('button', { name: /view details for dc01\.corp/i });
    fireEvent.click(btn);
    const dlg = screen.getByRole('dialog');
    expect(within(dlg).getByText('10.0.0.1')).toBeInTheDocument();          // ip — unique to drawer
    expect(within(dlg).getByText('Domain Controller')).toBeInTheDocument(); // role
  });

  it('marks the open row aria-current and clears it on close', async () => {
    server.use(http.get('/api/topology', () => HttpResponse.json(TOPOLOGY_RESPONSE)));
    setup();
    const btn = await screen.findByRole('button', { name: /view details for dc01\.corp/i });
    fireEvent.click(btn);
    expect(btn).toHaveAttribute('aria-current', 'true');
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(btn).toHaveAttribute('aria-current', 'false');
  });

  it('opens the drawer on load from a ?host= deep-link', async () => {
    server.use(http.get('/api/topology', () => HttpResponse.json(TOPOLOGY_RESPONSE)));
    render(
      <MemoryRouter initialEntries={['/topology?host=fw01.dmz']}>
        <Topology />
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
    expect(within(screen.getByRole('dialog')).getByText('192.168.1.1')).toBeInTheDocument();
  });

  it('clicking a sortable header does not open the drawer', async () => {
    server.use(http.get('/api/topology', () => HttpResponse.json(TOPOLOGY_RESPONSE)));
    setup();
    await screen.findByText('dc01.corp');
    fireEvent.click(screen.getByText('Hostname'));   // the <Th>
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('toElements builds zone compound containers + host pills with criticality + parent', () => {
    const els = toElements(TOPOLOGY_RESPONSE);
    const zones = els.filter((e) => e.data.node_type === 'zone');
    const hosts = els.filter((e) => e.data.node_type === 'host');
    expect(zones.map((z) => z.data.id).sort()).toEqual(['zone:corp', 'zone:dmz']);
    const dc = hosts.find((h) => h.data.id === 'host:dc01.corp');
    expect(dc!.data.parent).toBe('zone:corp');           // child of its zone container
    expect(dc!.data.criticality).toBe('CRITICAL');
    expect(dc!.data.label).toBe('dc01.corp');            // hostname is the in-node label
  });

  it('renders the graph view by default and passes host elements to Cytoscape', async () => {
    lastCyProps = null;
    server.use(http.get('/api/topology', () => HttpResponse.json(TOPOLOGY_RESPONSE)));
    render(<MemoryRouter initialEntries={['/']}><Topology /></MemoryRouter>);
    await waitFor(() => expect(screen.getByTestId('cy')).toBeInTheDocument());
    const ids = (lastCyProps.elements as any[]).map((e) => e.data.id);
    expect(ids).toContain('host:dc01.corp');
    expect(ids).toContain('zone:corp');
    // the table is NOT rendered in graph view
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });
});
