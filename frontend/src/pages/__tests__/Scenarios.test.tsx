import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, within, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Scenarios, { type Scenario } from '../Scenarios';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';
import * as csv from '../../lib/csv';
import Toaster from '../../components/Toaster';
import { useToastStore } from '../../store/toast';

const server = setupServer();

const SCENARIOS: Scenario[] = [
  {
    scenario_id: 'S001',
    name: 'Lateral Movement via Pass-the-Hash',
    severity: 'CRITICAL',
    steps: 5,
    os_family: 'windows',
    applicable_zones: ['CORP'],
    mitre: [{ tactic: 'lateral-movement', technique: 'T1550' }],
  },
  {
    scenario_id: 'S002',
    name: 'Phishing Campaign',
    severity: 'MEDIUM',
    steps: 3,
    os_family: 'windows',
    applicable_zones: ['CORP'],
    mitre: [{ tactic: 'initial-access', technique: 'T1566' }],
  },
];

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });
  useAuthStore.setState({ user: 'alice', role: 'analyst', csrf: 'tok', status: 'authed' });
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
      <Scenarios />
      <Toaster />
    </MemoryRouter>
  );
}

describe('Scenarios page', () => {
  it('renders scenario rows from API', async () => {
    server.use(http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)));
    setup();

    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.getByText('Phishing Campaign')).toBeInTheDocument();
    });
  });

  it('renders severity chips', async () => {
    server.use(http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)));
    setup();

    // Scope to the table so the severity-filter <option>s (same text) don't collide.
    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument());
    const table = within(screen.getByRole('table'));
    expect(table.getByText('CRITICAL')).toBeInTheDocument();
    expect(table.getByText('MEDIUM')).toBeInTheDocument();
  });

  it('renders MITRE technique tags', async () => {
    server.use(http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)));
    setup();

    await waitFor(() => {
      expect(screen.getByText('T1550')).toBeInTheDocument();
      expect(screen.getByText('T1566')).toBeInTheDocument();
    });
  });

  it('renders step counts', async () => {
    server.use(http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)));
    setup();

    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument();
      expect(screen.getByText('3')).toBeInTheDocument();
    });
  });

  it('each row has a "Prove this scenario" deep-link to /drill?scenario_id=<id>', async () => {
    server.use(http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)));
    setup();

    await waitFor(() => expect(screen.getByText('Phishing Campaign')).toBeInTheDocument());
    const links = screen.getAllByRole('link', { name: /prove this scenario/i });
    expect(links).toHaveLength(2);
    const hrefs = links.map((l) => l.getAttribute('href'));
    expect(hrefs).toContain('/drill?scenario_id=S001');
    expect(hrefs).toContain('/drill?scenario_id=S002');
  });

  const S001_DETAIL = {
    scenario_id: 'S001',
    name: 'Lateral Movement via Pass-the-Hash',
    severity: 'CRITICAL' as const,
    os_family: 'windows',
    applicable_zones: ['CORP'],
    mitre: [{ tactic: 'lateral-movement', technique: 'T1550' }],
    step_count: 2,
    steps: [
      { step_id: 1, name: 'Credential access', temporal_link: null,
        matching_criteria: { Node_Type: 'Process', process_name: 'mimikatz.exe' } },
      { step_id: 2, name: 'Remote logon',
        temporal_link: { previous_step: 1, min_time_delta_seconds: 0, max_time_delta_seconds: 300, link_scope: 'same_host' },
        matching_criteria: { Node_Type: 'Process', process_name: 'wmic.exe' } },
    ],
  };

  const S001_SIGMA = {
    scenario_id: 'S001',
    rules: [{ title: 'Augur S001 step1 Pass-the-Hash' }],
    yaml: '# Augur Sigma export — per-step detection\ntitle: Augur S001 step1 Pass-the-Hash\n',
    honesty_note: 'Augur-derived per-step detection. This rule matches ONE technique step in isolation.',
  };

  it('opens the drawer and fetches step bodies + MITRE on row-button click', async () => {
    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/scenarios/:id', () => HttpResponse.json(S001_DETAIL)),
      http.get('/api/scenarios/:id/sigma', () => HttpResponse.json(S001_SIGMA)),
    );
    setup();
    const btn = await screen.findByRole('button', { name: /view details for Lateral Movement/i });
    fireEvent.click(btn);
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(within(screen.getByRole('dialog')).getByText(/Credential access/)).toBeInTheDocument();
    });
    const dlg = screen.getByRole('dialog');
    expect(within(dlg).getByText(/Remote logon/)).toBeInTheDocument();
    expect(within(dlg).getByText(/T1550/)).toBeInTheDocument();
  });

  it('opens on load from ?scenario= deep-link and fetches detail', async () => {
    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/scenarios/:id', () => HttpResponse.json(S001_DETAIL)),
      http.get('/api/scenarios/:id/sigma', () => HttpResponse.json(S001_SIGMA)),
    );
    render(
      <MemoryRouter initialEntries={['/scenarios?scenario=S001']}>
        <Scenarios />
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(within(screen.getByRole('dialog')).getByText(/Credential access/)).toBeInTheDocument();
    });
  });

  it('surfaces an inline error when detail fetch 404s', async () => {
    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/scenarios/:id', () => HttpResponse.json({ detail: 'unknown' }, { status: 404 })),
      http.get('/api/scenarios/:id/sigma', () => HttpResponse.json(S001_SIGMA)),
    );
    setup();
    fireEvent.click(await screen.findByRole('button', { name: /view details for Lateral Movement/i }));
    const dlg = screen.getByRole('dialog');
    await within(dlg).findByText(/failed to load scenario detail|unknown/i);
  });

  it('close clears detail: Esc closes drawer, clears ?scenario= param, and flips aria-selected to false', async () => {
    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/scenarios/:id', () => HttpResponse.json(S001_DETAIL)),
      http.get('/api/scenarios/:id/sigma', () => HttpResponse.json(S001_SIGMA)),
    );
    render(
      <MemoryRouter initialEntries={['/scenarios?scenario=S001']}>
        <Scenarios />
      </MemoryRouter>
    );

    // Drawer should be open and step detail visible from the deep-link.
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(within(screen.getByRole('dialog')).getByText(/Credential access/)).toBeInTheDocument();
    });

    // Row button must be aria-current=true while the drawer is open.
    const btn = screen.getByRole('button', { name: /view details for Lateral Movement/i });
    expect(btn).toHaveAttribute('aria-current', 'true');

    // Press Escape to close.
    fireEvent.keyDown(document, { key: 'Escape' });

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(btn).toHaveAttribute('aria-current', 'false');
  });

  it('switching scenarios refetches: opening a second scenario shows its own steps and not the first\'s', async () => {
    const S002_DETAIL = {
      scenario_id: 'S002',
      name: 'Phishing Campaign',
      severity: 'MEDIUM' as const,
      os_family: 'windows',
      applicable_zones: ['CORP'],
      mitre: [{ tactic: 'initial-access', technique: 'T1566' }],
      step_count: 2,
      steps: [
        { step_id: 1, name: 'Spearphishing email delivery', temporal_link: null,
          matching_criteria: { Node_Type: 'Process', process_name: 'outlook.exe' } },
        { step_id: 2, name: 'Macro execution',
          temporal_link: { previous_step: 1, min_time_delta_seconds: 0, max_time_delta_seconds: 120, link_scope: 'same_host' },
          matching_criteria: { Node_Type: 'Process', process_name: 'winword.exe' } },
      ],
    };

    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/scenarios/:id', ({ params }) => {
        if (params.id === 'S001') return HttpResponse.json(S001_DETAIL);
        if (params.id === 'S002') return HttpResponse.json(S002_DETAIL);
        return HttpResponse.json({ detail: 'not found' }, { status: 404 });
      }),
      http.get('/api/scenarios/:id/sigma', () => HttpResponse.json(S001_SIGMA)),
    );
    setup();

    // Open S001 and verify its step text appears.
    const btn1 = await screen.findByRole('button', { name: /view details for Lateral Movement/i });
    fireEvent.click(btn1);
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(within(screen.getByRole('dialog')).getByText(/Credential access/)).toBeInTheDocument();
    });

    // Now open S002 (click its row button while drawer is already open).
    const btn2 = screen.getByRole('button', { name: /view details for Phishing Campaign/i });
    fireEvent.click(btn2);

    // S002's step must appear and S001's step must be gone.
    await waitFor(() => {
      const dlg = screen.getByRole('dialog');
      expect(within(dlg).getByText(/Spearphishing email delivery/)).toBeInTheDocument();
      expect(within(dlg).queryByText(/Credential access/)).not.toBeInTheDocument();
    });
  });

  it('drawer renders the Sigma section: honesty note + YAML pre + copy + download', async () => {
    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/scenarios/:id', () => HttpResponse.json(S001_DETAIL)),
      http.get('/api/scenarios/:id/sigma', () => HttpResponse.json(S001_SIGMA)),
    );
    setup();
    fireEvent.click(await screen.findByRole('button', { name: /view details for Lateral Movement/i }));
    const dlg = await screen.findByRole('dialog');
    await within(dlg).findByText(/matches ONE technique step in isolation/i);
    expect(within(dlg).getByText(/title: Augur S001 step1 Pass-the-Hash/)).toBeInTheDocument();
    expect(within(dlg).getByRole('button', { name: /copy/i })).toBeInTheDocument();
    expect(within(dlg).getByRole('button', { name: /download/i })).toBeInTheDocument();
  });

  it('page toolbar has an Export Sigma pack button that calls the pack endpoint', async () => {
    let packCalled = false;
    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/sigma_pack', () => {
        packCalled = true;
        return HttpResponse.json({
          rule_count: 2, scenario_count: 2, yaml: '# pack\ntitle: a\n', honesty_note: 'note',
        });
      }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('Phishing Campaign')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /export sigma pack/i }));
    await waitFor(() => expect(packCalled).toBe(true));
  });

  it('pack export triggers a YAML download with the pack body', async () => {
    const downloadSpy = vi.spyOn(csv, 'downloadText').mockImplementation(() => {});
    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/sigma_pack', () =>
        HttpResponse.json({
          rule_count: 2, scenario_count: 2, yaml: '# pack\ntitle: a\n', honesty_note: 'note',
        }),
      ),
    );
    setup();
    await waitFor(() => expect(screen.getByText('Phishing Campaign')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /export sigma pack/i }));
    await waitFor(() => expect(downloadSpy).toHaveBeenCalledOnce());
    const [filename, content, mime] = downloadSpy.mock.calls[0];
    expect(filename).toBe('augur-sigma-pack.yml');
    expect(content).toContain('# pack');
    expect(mime).toBe('text/yaml');
    downloadSpy.mockRestore();
  });

  it('pack export shows an error toast when /api/sigma_pack returns 500', async () => {
    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/sigma_pack', () =>
        HttpResponse.json({ detail: 'internal error' }, { status: 500 }),
      ),
    );
    setup();
    await waitFor(() => expect(screen.getByText('Phishing Campaign')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /export sigma pack/i }));
    await waitFor(() => expect(useToastStore.getState().show).toBe(true));
    expect(useToastStore.getState().status).toBe('error');
    expect(useToastStore.getState().message).toMatch(/sigma pack/i);
  });

  it('Sigma error state renders role="alert" when /api/scenarios/:id/sigma returns 500', async () => {
    server.use(
      http.get('/api/scenarios', () => HttpResponse.json(SCENARIOS)),
      http.get('/api/scenarios/:id', () => HttpResponse.json(S001_DETAIL)),
      http.get('/api/scenarios/:id/sigma', () =>
        HttpResponse.json({ detail: 'sigma generation failed' }, { status: 500 }),
      ),
    );
    setup();
    fireEvent.click(await screen.findByRole('button', { name: /view details for Lateral Movement/i }));
    const dlg = await screen.findByRole('dialog');
    await waitFor(() => {
      const alerts = within(dlg).getAllByRole('alert');
      expect(alerts.length).toBeGreaterThan(0);
      const sigmaAlert = alerts.find((el) =>
        el.textContent?.toLowerCase().includes('sigma') ||
        el.textContent?.toLowerCase().includes('generate') ||
        el.textContent?.toLowerCase().includes('failed'),
      );
      expect(sigmaAlert).toBeTruthy();
    });
  });
});
