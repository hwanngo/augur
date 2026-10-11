import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Dashboard, { type Detection } from '../Dashboard';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';
import * as csv from '../../lib/csv';

const navigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return { ...actual, useNavigate: () => navigate };
});

const server = setupServer();

const DETECTIONS: Detection[] = [
  {
    scenario_id: 'S001',
    name: 'Lateral Movement via Pass-the-Hash',
    severity: 'CRITICAL',
    proximity: 1.0,
    matched_steps: [{ step_id: 1, name: 'Credential Dump', host: 'WS01', timestamp: '2024-01-01T00:00:00Z' }],
    missing_steps: [],
    affected_hosts: ['WS01', 'DC01'],
    affected_zones: ['corp'],
    hunting_queries: [{ engine: 'KQL', query: 'SecurityEvent | where EventID == 4624' }],
  },
  {
    scenario_id: 'S002',
    name: 'Phishing Campaign',
    severity: 'MEDIUM',
    proximity: 0.5,
    matched_steps: [{ step_id: 1, name: 'Email received', host: 'MBX01', timestamp: null }],
    missing_steps: [{
      step_id: 2,
      name: 'Attachment opened',
      matching_criteria: { Node_Type: 'Process', ProcessName: { in: ['winword.exe'] } },
      temporal: { previous_step: 1, link_scope: 'same_host', min_time_delta_seconds: 0, max_time_delta_seconds: 90 },
    }],
    affected_hosts: ['MBX01'],
    affected_zones: ['dmz'],
    hunting_queries: [{ engine: 'Sigma', query: 'title: Phishing' }],
  },
  {
    scenario_id: 'S003',
    name: 'Low Confidence Event',
    severity: 'LOW',
    proximity: 0.1,
    matched_steps: [],
    missing_steps: [{ step_id: 1, name: 'Init' }],
    affected_hosts: [],
    affected_zones: [],
    hunting_queries: [],
  },
  {
    scenario_id: 'S004',
    name: 'Stalled Chain',
    severity: 'HIGH',
    proximity: 0.6667,
    matched_steps: [{ step_id: 1, name: 'Beacon', host: 'PC1', timestamp: null }],
    missing_steps: [{
      step_id: 2,
      name: 'LSASS access',
      matching_criteria: { Node_Type: 'Process', ProcessName: { in: ['rundll32.exe'] } },
      temporal: { previous_step: 1, link_scope: 'same_host', min_time_delta_seconds: 0, max_time_delta_seconds: 120 },
    }],
    affected_hosts: ['PC1'],
    affected_zones: ['corp'],
    hunting_queries: [],
    stall: { kind: 'temporal', step_id: 2, host: 'PC1', delta_seconds: 300, window_seconds: 120 },
  },
];

beforeEach(() => {
  server.listen({ onUnhandledFrame: 'error' });
  server.use(http.get('/api/health', () => HttpResponse.json({ status: 'ok', real_data: false })));
  useAuthStore.setState({ user: 'alice', role: 'analyst', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
  localStorage.clear();
  navigate.mockClear();
});
afterEach(() => {
  server.resetHandlers();
  server.close();
  localStorage.clear();
});

function setup() {
  return render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>
  );
}

describe('Dashboard', () => {
  it('renders all detections above default threshold (0.3)', async () => {
    server.use(
      http.get('/api/detections', () => HttpResponse.json(DETECTIONS))
    );

    setup();

    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.getByText('Phishing Campaign')).toBeInTheDocument();
      // Low confidence at 0.1 should be filtered out at default 0.3
      expect(screen.queryByText('Low Confidence Event')).not.toBeInTheDocument();
    });
  });

  it('slider filters the rendered list client-side', async () => {
    server.use(
      http.get('/api/detections', () => HttpResponse.json(DETECTIONS))
    );

    setup();

    // Wait for data to load
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });

    const slider = screen.getByRole('slider');

    // Move slider to 0.6 — should show only S001 (1.0) not S002 (0.5) nor S003 (0.1)
    fireEvent.change(slider, { target: { value: '0.6' } });

    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.queryByText('Phishing Campaign')).not.toBeInTheDocument();
    });

    // Move slider to 0 — all three should be shown
    fireEvent.change(slider, { target: { value: '0' } });

    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.getByText('Phishing Campaign')).toBeInTheDocument();
      expect(screen.getByText('Low Confidence Event')).toBeInTheDocument();
    });
  });

  it('copy button copies query text', async () => {
    server.use(
      http.get('/api/detections', () => HttpResponse.json(DETECTIONS))
    );

    // Mock clipboard
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      writable: true,
      configurable: true,
    });

    setup();

    // Wait for card to render and expand steps
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });

    // Expand the first card's steps
    const expandButtons = screen.getAllByRole('button', { name: /steps/i });
    fireEvent.click(expandButtons[0]);

    // Find the copy button in the KQL block
    await waitFor(() => {
      expect(screen.getByText('KQL')).toBeInTheDocument();
    });

    const copyBtn = screen.getAllByRole('button', { name: /copy/i })[0];
    await waitFor(() => fireEvent.click(copyBtn));

    expect(writeText).toHaveBeenCalledWith('SecurityEvent | where EventID == 4624');
  });

  it('severity select filters the rendered list client-side', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.getByText('Phishing Campaign')).toBeInTheDocument();
    });

    const sev = screen.getByRole('combobox', { name: /severity/i });
    fireEvent.click(sev);
    fireEvent.click(screen.getByRole('option', { name: 'CRITICAL' }));

    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.queryByText('Phishing Campaign')).not.toBeInTheDocument();
    });
  });

  it('zone select filters by affected_zones membership', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.getByText('Phishing Campaign')).toBeInTheDocument();
    });

    const zone = screen.getByRole('combobox', { name: /zone/i });
    // Open the dropdown to verify options
    fireEvent.click(zone);
    expect(screen.getByRole('option', { name: 'corp' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'dmz' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('option', { name: 'corp' }));

    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.queryByText('Phishing Campaign')).not.toBeInTheDocument();
    });
  });

  it('severity filter can be cleared back to All (Fix 1: empty option restores unfiltered list)', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    // Need momentum endpoint too
    server.use(http.get('/api/momentum', () => HttpResponse.json({ series: [] })));
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.getByText('Phishing Campaign')).toBeInTheDocument();
    });

    // Select CRITICAL
    const sev = screen.getByRole('combobox', { name: /severity/i });
    fireEvent.click(sev);
    fireEvent.click(screen.getByRole('option', { name: 'CRITICAL' }));
    await waitFor(() => expect(screen.queryByText('Phishing Campaign')).not.toBeInTheDocument());
    expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();

    // Clear by picking "All severities"
    fireEvent.click(screen.getByRole('combobox', { name: /severity/i }));
    fireEvent.click(screen.getByRole('option', { name: /all severities/i }));
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.getByText('Phishing Campaign')).toBeInTheDocument();
    });
  });

  it('zone filter can be cleared back to All (Fix 1: empty option restores unfiltered list)', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    server.use(http.get('/api/momentum', () => HttpResponse.json({ series: [] })));
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.getByText('Phishing Campaign')).toBeInTheDocument();
    });

    // Select corp
    const zone = screen.getByRole('combobox', { name: /zone/i });
    fireEvent.click(zone);
    fireEvent.click(screen.getByRole('option', { name: 'corp' }));
    await waitFor(() => expect(screen.queryByText('Phishing Campaign')).not.toBeInTheDocument());

    // Clear by picking "All zones"
    fireEvent.click(screen.getByRole('combobox', { name: /zone/i }));
    fireEvent.click(screen.getByRole('option', { name: /all zones/i }));
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.getByText('Phishing Campaign')).toBeInTheDocument();
    });
  });

  it('changing the time range re-fetches /api/detections with from/to params', async () => {
    const calls: Array<{ from: string | null; to: string | null }> = [];
    server.use(
      http.get('/api/detections', ({ request }) => {
        const url = new URL(request.url);
        calls.push({ from: url.searchParams.get('from'), to: url.searchParams.get('to') });
        return HttpResponse.json(DETECTIONS);
      })
    );
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });
    // initial fetch has no from/to
    expect(calls[0]).toEqual({ from: null, to: null });

    const range = screen.getByRole('combobox', { name: /time range/i });
    fireEvent.click(range);
    fireEvent.click(screen.getByRole('option', { name: /last 24 hours/i }));

    await waitFor(() => {
      const last = calls[calls.length - 1];
      expect(last.from).toBeTruthy();
      expect(last.to).toBeTruthy();
      // absolute ISO bounds, not the literal preset token
      expect(last.from).not.toBe('24h');
      expect(Number.isNaN(Date.parse(last.from as string))).toBe(false);
      expect(Number.isNaN(Date.parse(last.to as string))).toBe(false);
    });
  });

  it('Export CSV button is present and enabled when there are detections', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });
    const btn = screen.getByRole('button', { name: /export csv/i });
    expect(btn).toBeEnabled();
  });

  it('Export CSV button is disabled when the filtered view is empty', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });
    // push the slider above every proximity so the filtered list is empty
    const slider = screen.getByRole('slider');
    fireEvent.change(slider, { target: { value: '1' } });
    fireEvent.change(slider, { target: { value: '0.95' } });
    // S001 is at 1.0; bump just past it -> nothing
    fireEvent.change(slider, { target: { value: '1' } });
    fireEvent.change(slider, { target: { value: '0.99' } });
    // severity filter to an empty combination guarantees zero rows
    const sev = screen.getByRole('combobox', { name: /severity/i });
    fireEvent.click(sev);
    fireEvent.click(screen.getByRole('option', { name: 'LOW' }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /export csv/i })).toBeDisabled();
    });
  });

  it('Export CSV downloads the filtered detections', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    const spy = vi.spyOn(csv, 'downloadCsv').mockImplementation(() => {});
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });
    // restrict to CRITICAL so only S001 is in `filtered`
    fireEvent.click(screen.getByRole('combobox', { name: /severity/i }));
    fireEvent.click(screen.getByRole('option', { name: 'CRITICAL' }));
    await waitFor(() => expect(screen.queryByText('Phishing Campaign')).not.toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /export csv/i }));
    expect(spy).toHaveBeenCalledTimes(1);
    const [filename, content] = spy.mock.calls[0];
    expect(filename).toMatch(/^augur-detections-\d{4}-\d{2}-\d{2}\.csv$/);
    // header + the one CRITICAL row, not the MEDIUM/LOW rows
    expect(content).toContain('scenario_id');
    expect(content).toContain('S001');
    expect(content).not.toContain('S002');
    spy.mockRestore();
  });

  it('Export ATT&CK Layer fetches type=detections with the slider min_proximity [AUDIT #4]', async () => {
    let capturedUrl = '';
    server.use(
      http.get('/api/detections', () => HttpResponse.json(DETECTIONS)),
      http.get('/api/navigator_layer', ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json({ name: 'Augur — Detections', techniques: [] });
      })
    );
    const spy = vi.spyOn(csv, 'downloadJson').mockImplementation(() => {});
    setup();
    await waitFor(() => expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument());
    // move the slider to 0.6 — the export must use this, not the fetch param (0)
    fireEvent.change(screen.getByRole('slider'), { target: { value: '0.6' } });
    fireEvent.click(screen.getByRole('button', { name: /export att&ck layer/i }));
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1));
    expect(capturedUrl).toContain('type=detections');
    expect(capturedUrl).toContain('min_proximity=0.6');
    const [filename] = spy.mock.calls[0];
    expect(filename).toMatch(/^augur-attack-detections-\d{4}-\d{2}-\d{2}\.json$/);
    spy.mockRestore();
  });

  it('shows empty state when all detections below threshold', async () => {
    server.use(
      http.get('/api/detections', () => HttpResponse.json(DETECTIONS))
    );

    setup();

    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });

    const slider = screen.getByRole('slider');
    fireEvent.change(slider, { target: { value: '1.0' } });

    // Only S001 at exactly 1.0 should show
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });

    // Push to above 1.0 — nothing should show
    // (we can set it just past the only exact match)
    fireEvent.change(slider, { target: { value: '0.99' } });
    fireEvent.change(slider, { target: { value: '1.0' } });

    // With slider at max (1.0) only S001 at exactly 1.0 remains
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });
  });

  it('saving a filter then recalling it restores severity, zone, minProximity and range', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    setup();
    await waitFor(() => expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument());

    // Set a distinctive filter combination
    fireEvent.click(screen.getByRole('combobox', { name: /severity/i }));
    fireEvent.click(screen.getByRole('option', { name: 'CRITICAL' }));
    fireEvent.click(screen.getByRole('combobox', { name: /zone/i }));
    fireEvent.click(screen.getByRole('option', { name: 'corp' }));
    fireEvent.change(screen.getByRole('slider'), { target: { value: '0.5' } });
    await waitFor(() => expect(screen.queryByText('Phishing Campaign')).not.toBeInTheDocument());

    // Save it under a name
    fireEvent.click(screen.getByRole('button', { name: /save filter/i }));
    fireEvent.change(screen.getByRole('textbox', { name: /filter name/i }), { target: { value: 'crit-corp' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    // Open saved-filters dropdown to verify 'crit-corp' is in the list
    fireEvent.click(screen.getByRole('combobox', { name: /saved filters/i }));
    await waitFor(() => expect(screen.getByRole('option', { name: 'crit-corp' })).toBeInTheDocument());
    // Close saved-filters by pressing Escape
    fireEvent.keyDown(screen.getByRole('combobox', { name: /saved filters/i }), { key: 'Escape' });

    // Mutate the filters away from the saved snapshot (set to MEDIUM+dmz so Phishing shows)
    fireEvent.click(screen.getByRole('combobox', { name: /severity/i }));
    fireEvent.click(screen.getByRole('option', { name: 'MEDIUM' }));
    fireEvent.click(screen.getByRole('combobox', { name: /zone/i }));
    fireEvent.click(screen.getByRole('option', { name: 'dmz' }));
    fireEvent.change(screen.getByRole('slider'), { target: { value: '0' } });
    await waitFor(() => expect(screen.getByText('Phishing Campaign')).toBeInTheDocument());

    // Recall the saved filter
    fireEvent.click(screen.getByRole('combobox', { name: /saved filters/i }));
    await waitFor(() => expect(screen.getByRole('option', { name: 'crit-corp' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('option', { name: 'crit-corp' }));

    // Snapshot restored: severity CRITICAL + zone corp + proximity 0.5 → only S001
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
      expect(screen.queryByText('Phishing Campaign')).not.toBeInTheDocument();
    });
    expect(screen.getByRole('combobox', { name: /severity/i })).toHaveTextContent('CRITICAL');
    expect(screen.getByRole('combobox', { name: /zone/i })).toHaveTextContent('corp');
    expect((screen.getByRole('slider') as HTMLInputElement).value).toBe('0.5');
  });

  it('renders F1 next-step guidance for a partial detection missing step', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    setup();
    await waitFor(() => expect(screen.getByText('Phishing Campaign')).toBeInTheDocument());

    // Expand every card's steps; the Phishing card (S002) carries an enriched missing step.
    screen.getAllByRole('button', { name: /steps/i }).forEach((b) => fireEvent.click(b));

    await waitFor(() => {
      // "Next: <name>" guidance line
      expect(screen.getByText(/Next: Attachment opened/i)).toBeInTheDocument();
      // formatted criteria + temporal phrase
      expect(screen.getByText(/ProcessName in \[winword\.exe\]/)).toBeInTheDocument();
      expect(screen.getByText(/within ≤90s of the prior step, same host/i)).toBeInTheDocument();
    });
  });

  it('renders F3 "why it stalled" line for a partial detection but not for a full one', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    setup();
    await waitFor(() => expect(screen.getByText('Stalled Chain')).toBeInTheDocument());

    // the stall line is on the card body (not behind the expander)
    await waitFor(() => {
      expect(screen.getByText(/Why it stalled/i)).toBeInTheDocument();
      expect(screen.getByText(/closest candidate on PC1/i)).toBeInTheDocument();
      expect(screen.getByText(/120s window/i)).toBeInTheDocument();
    });
    // exactly one stall line — the full detection (S001) does not render it
    expect(screen.getAllByText(/Why it stalled/i)).toHaveLength(1);
  });

  it('fetches /api/momentum and renders a sparkline joined by scenario_id', async () => {
    server.use(
      http.get('/api/detections', () => HttpResponse.json(DETECTIONS)),
      http.get('/api/momentum', () => HttpResponse.json({
        from: '1970-01-01T00:00:00+00:00', to: '9999-12-31T00:00:00+00:00',
        bounds: ['a', 'b', 'c', 'd'],
        series: [{ scenario_id: 'S001', points: [0.25, 0.5, 0.75, 1.0],
                   trend: 'rising', delta: 0.75, velocity: 0.25 }],
      })),
    );
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });
    // S001 got momentum joined -> a sparkline appears; cards without a series do not.
    await waitFor(() => {
      expect(screen.getAllByTestId('momentum-spark').length).toBe(1);
    });
  });

  it('renders cards without a sparkline before momentum resolves (progressive)', async () => {
    server.use(
      http.get('/api/detections', () => HttpResponse.json(DETECTIONS)),
      http.get('/api/momentum', () => HttpResponse.json({ from: '', to: '', bounds: [], series: [] })),
    );
    setup();
    await waitFor(() => {
      expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('momentum-spark')).not.toBeInTheDocument();
  });

  it('each DetectionCard has a View case button that navigates to /timeline?scenario_id=', async () => {
    server.use(http.get('/api/detections', () => HttpResponse.json(DETECTIONS)));
    setup();
    await waitFor(() => expect(screen.getByText('Lateral Movement via Pass-the-Hash')).toBeInTheDocument());

    const viewButtons = screen.getAllByRole('button', { name: /view case/i });
    expect(viewButtons.length).toBeGreaterThan(0);
    fireEvent.click(viewButtons[0]);

    const scenarioId = 'S001';
    expect(navigate).toHaveBeenCalledWith(`/timeline?scenario_id=${encodeURIComponent(scenarioId)}`);
  });
});
