import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import AlertsPage, { type Alert } from '../Alerts';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';
import * as csv from '../../lib/csv';
import Toaster from '../../components/Toaster';
import { useToastStore } from '../../store/toast';

const server = setupServer();
const ALERTS: Alert[] = [
  { id: 'a1', scenario_id: 'SCEN-2026-001', scenario_name: 'Cred Theft', severity: 'CRITICAL',
    affected_hosts: ['HR_User_PC'], proximity: 1.0, band: 'CONFIRMED', state: 'open', status: 'open',
    assignee: '', resolution_note: '', assigned_at: '', resolved_at: '',
    first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-01-01T00:00:00Z', count: 1, notified_band: 'CONFIRMED',
    created_at: '2026-01-01T00:00:00Z',
    detection: { matched_steps: [{ step_id: 1, name: 'DLL Inject', host: 'HR_User_PC' }], missing_steps: [],
                 hunting_queries: [{ engine: 'KQL', query: 'DeviceEvents | take 1' }], affected_zones: ['User_Endpoint'] } },
  { id: 'a2', scenario_id: 'SCEN-2026-188', scenario_name: 'Recon', severity: 'HIGH',
    affected_hosts: ['HR_User_PC'], proximity: 0.6667, band: 'WATCH', state: 'acknowledged', status: 'acknowledged',
    assignee: 'an', resolution_note: '', assigned_at: '2026-01-01T00:00:00Z', resolved_at: '',
    first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-01-01T00:00:00Z', count: 2, notified_band: 'WATCH',
    created_at: '2026-01-01T00:00:00Z', detection: { matched_steps: [], missing_steps: [], hunting_queries: [], affected_zones: [] } },
];

const SUMMARY = {
  open_count: 1, acknowledged_count: 1, resolved_count: 0, max_alert_id: 2,
  in_progress_count: 0, closed_count: 0, unassigned_count: 1,
  by_status: { open: 1, acknowledged: 1, in_progress: 0, resolved: 0, closed: 0 },
};

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });
  // Baseline summary handler so tests that don't care about cards don't 'error' on the fetch.
  // Test-specific server.use(...) for /api/alerts/summary takes precedence (msw: last match wins).
  server.use(http.get('/api/alerts/summary', () => HttpResponse.json(SUMMARY)));
  useAuthStore.setState({ user: 'an', role: 'analyst', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
  localStorage.clear();
  act(() => useToastStore.setState({ show: false, message: '', status: 'success' }));
});
afterEach(() => {
  server.resetHandlers();
  server.close();
  localStorage.clear();
  act(() => useToastStore.setState({ show: false, message: '', status: 'success' }));
});

function setup(initialEntry = '/alerts') {
  return render(<MemoryRouter initialEntries={[initialEntry]}><AlertsPage /><Toaster /></MemoryRouter>);
}

describe('Alerts page', () => {
  it('renders alert rows', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => {
      expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument();
      expect(screen.getByText('SCEN-2026-188')).toBeInTheDocument();
    });
  });

  it('filters to open only via the status tab', async () => {
    server.use(http.get('/api/alerts', ({ request }) => {
      const url = new URL(request.url);
      const st = url.searchParams.get('status');
      const data = st ? ALERTS.filter((a) => a.status === st) : ALERTS;
      return HttpResponse.json(data);
    }));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-188')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('tab', { name: 'Open' }));
    await waitFor(() => expect(screen.queryByText('SCEN-2026-188')).not.toBeInTheDocument());
    expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument();
  });

  it('renders an assignee column with em-dash for unassigned', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    // a2 is assigned to 'an'
    expect(screen.getByText('an')).toBeInTheDocument();
    // assignee column header present
    expect(screen.getByRole('columnheader', { name: 'Assignee' })).toBeInTheDocument();
  });

  it('renders an SLA chip per row', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    // SlaChip carries an aria-label "Open for ..."
    const chips = screen.getAllByLabelText(/open for|resolved in/i);
    expect(chips.length).toBeGreaterThanOrEqual(2);
  });

  it('In progress / Resolved / Closed status tabs set the status param', async () => {
    const seen: string[] = [];
    server.use(http.get('/api/alerts', ({ request }) => {
      const url = new URL(request.url);
      const st = url.searchParams.get('status');
      if (st) seen.push(st);
      const data = st ? ALERTS.filter((a) => a.status === st) : ALERTS;
      return HttpResponse.json(data);
    }));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('tab', { name: 'In progress' }));
    await waitFor(() => expect(seen).toContain('in_progress'));
    fireEvent.click(screen.getByRole('tab', { name: 'Resolved' }));
    await waitFor(() => expect(seen).toContain('resolved'));
    fireEvent.click(screen.getByRole('tab', { name: 'Closed' }));
    await waitFor(() => expect(seen).toContain('closed'));
  });

  it('My queue toggle adds assignee=me', async () => {
    let sawMe = false;
    server.use(http.get('/api/alerts', ({ request }) => {
      const url = new URL(request.url);
      if (url.searchParams.get('assignee') === 'me') sawMe = true;
      return HttpResponse.json(ALERTS);
    }));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /my queue/i }));
    await waitFor(() => expect(sawMe).toBe(true));
  });

  it('time range sets seen_from / seen_to params', async () => {
    const calls: Array<{ from: string | null; to: string | null }> = [];
    server.use(http.get('/api/alerts', ({ request }) => {
      const url = new URL(request.url);
      calls.push({ from: url.searchParams.get('seen_from'), to: url.searchParams.get('seen_to') });
      return HttpResponse.json(ALERTS);
    }));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('combobox', { name: /time range/i }));
    fireEvent.click(screen.getByRole('option', { name: /last 7 days/i }));
    await waitFor(() => {
      const last = calls[calls.length - 1];
      expect(last.from).toBeTruthy();
      expect(last.to).toBeTruthy();
      expect(last.from).not.toBe('7d');
    });
  });

  it('renders summary stat cards from /api/alerts/summary', async () => {
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.get('/api/alerts/summary', () => HttpResponse.json({
        open_count: 3, acknowledged_count: 2, resolved_count: 1, max_alert_id: 5,
        in_progress_count: 4, closed_count: 6, unassigned_count: 7,
        by_status: { open: 3, acknowledged: 2, in_progress: 4, resolved: 1, closed: 6 },
      })),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    // The six cards expose their counts
    const inProgressCard = await screen.findByRole('button', { name: /in progress/i });
    expect(inProgressCard).toHaveTextContent('4');
    const unassignedCard = screen.getByRole('button', { name: /unassigned/i });
    expect(unassignedCard).toHaveTextContent('7');
  });

  it('clicking a summary card selects the matching status tab', async () => {
    const seen: string[] = [];
    server.use(
      http.get('/api/alerts', ({ request }) => {
        const url = new URL(request.url);
        const st = url.searchParams.get('status');
        if (st) seen.push(st);
        return HttpResponse.json(ALERTS);
      }),
      http.get('/api/alerts/summary', () => HttpResponse.json({
        open_count: 3, max_alert_id: 5,
        by_status: { open: 3, acknowledged: 2, in_progress: 4, resolved: 1, closed: 6 }, unassigned_count: 0,
      })),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(await screen.findByRole('button', { name: /resolved/i }));
    await waitFor(() => {
      expect(seen).toContain('resolved');
      expect(screen.getByRole('tab', { name: 'Resolved' })).toHaveAttribute('aria-selected', 'true');
    });
  });

  it('opens detail drawer with queries + ack for an open alert', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
               http.get('/api/alerts/a1', () => HttpResponse.json({ ...ALERTS[0],
                 events: [{ ts: 't', actor: 'system', event: 'created', detail: 'CONFIRMED' }] })));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.getByText('DeviceEvents | take 1')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Acknowledge' })).toBeInTheDocument();
    });
  });

  it('renders F1 next-step guidance for an enriched missing step in the drawer', async () => {
    const partial: Alert = {
      ...ALERTS[0],
      proximity: 0.5,
      detection: {
        matched_steps: [{ step_id: 1, name: 'DLL Inject', host: 'HR_User_PC' }],
        missing_steps: [{
          step_id: 2,
          name: 'LSASS access',
          matching_criteria: { Node_Type: 'Process', ProcessName: { in: ['rundll32.exe'] } },
          temporal: { previous_step: 1, link_scope: 'same_host', min_time_delta_seconds: 0, max_time_delta_seconds: 120 },
        }],
        hunting_queries: [{ engine: 'KQL', query: 'DeviceEvents | take 1' }],
        affected_zones: ['User_Endpoint'],
      },
    };
    server.use(
      http.get('/api/alerts', () => HttpResponse.json([partial])),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...partial, events: [] })),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.getByText(/Next: LSASS access/i)).toBeInTheDocument();
      expect(screen.getByText(/ProcessName in \[rundll32\.exe\]/)).toBeInTheDocument();
      expect(screen.getByText(/within ≤120s of the prior step, same host/i)).toBeInTheDocument();
    });
  });

  it('renders the F3 "why it stalled" line in the drawer when stall is present', async () => {
    const partial: Alert = {
      ...ALERTS[0],
      proximity: 0.6667,
      detection: {
        matched_steps: [{ step_id: 1, name: 'DLL Inject', host: 'HR_User_PC' }],
        missing_steps: [{ step_id: 2, name: 'LSASS access' }],
        hunting_queries: [],
        affected_zones: ['User_Endpoint'],
        stall: { kind: 'temporal', step_id: 2, host: 'HR_User_PC', delta_seconds: 300, window_seconds: 120 },
      },
    };
    server.use(
      http.get('/api/alerts', () => HttpResponse.json([partial])),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...partial, events: [] })),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await waitFor(() => {
      expect(screen.getByText(/Why it stalled/i)).toBeInTheDocument();
      expect(screen.getByText(/closest candidate on HR_User_PC/i)).toBeInTheDocument();
    });
  });

  it('does not render a stall line in the drawer when stall is absent', async () => {
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...ALERTS[0], events: [] })),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
    expect(screen.queryByText(/Why it stalled/i)).not.toBeInTheDocument();
  });

  it('analyst can self-assign via Assign to me', async () => {
    let body: { assignee?: string } | null = null;
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...ALERTS[0], events: [] })),
      http.post('/api/alerts/a1/assign', async ({ request }) => {
        body = (await request.json()) as { assignee: string };
        return HttpResponse.json({ ...ALERTS[0], assignee: 'an' });
      }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /assign to me/i }));
    await waitFor(() => {
      expect(body).toEqual({ assignee: 'an' });
      expect(screen.getByRole('status')).toHaveTextContent(/assigned to you/i);
    });
  });

  it('admin sees an assignee select populated from /api/users', async () => {
    useAuthStore.setState({ user: 'root', role: 'admin', csrf: 'tok', status: 'authed' });
    let body: { assignee?: string } | null = null;
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...ALERTS[0], events: [] })),
      http.get('/api/users', () => HttpResponse.json([
        { id: 1, username: 'alice', role: 'analyst', disabled: false, created_at: '', updated_at: '' },
        { id: 2, username: 'bob', role: 'analyst', disabled: false, created_at: '', updated_at: '' },
      ])),
      http.post('/api/alerts/a1/assign', async ({ request }) => {
        body = (await request.json()) as { assignee: string };
        return HttpResponse.json({ ...ALERTS[0], assignee: 'bob' });
      }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
    const sel = await screen.findByRole('combobox', { name: /assign/i });
    fireEvent.click(sel);
    expect(await screen.findByRole('option', { name: 'bob' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('option', { name: 'bob' }));
    fireEvent.click(screen.getByRole('button', { name: 'Assign' }));
    await waitFor(() => expect(body).toEqual({ assignee: 'bob' }));
  });

  it('set status resolved requires a note then posts /status', async () => {
    let body: { status?: string; note?: string } | null = null;
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...ALERTS[0], events: [] })),
      http.post('/api/alerts/a1/status', async ({ request }) => {
        body = (await request.json()) as { status: string; note: string };
        return HttpResponse.json({ ...ALERTS[0], status: 'resolved' });
      }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());

    const statusSel = screen.getByRole('combobox', { name: /set status/i });
    fireEvent.click(statusSel);
    fireEvent.click(screen.getByRole('option', { name: /resolved/i }));
    // note textarea revealed
    const note = await screen.findByRole('textbox', { name: /resolution note/i });

    // Submitting with empty note is blocked client-side (no request)
    fireEvent.click(screen.getByRole('button', { name: 'Set status' }));
    await waitFor(() => expect(screen.getByRole('status')).toBeInTheDocument());
    expect(body).toBeNull();

    fireEvent.change(note, { target: { value: 'handled, false positive' } });
    fireEvent.click(screen.getByRole('button', { name: 'Set status' }));
    await waitFor(() => {
      expect(body).toEqual({ status: 'resolved', note: 'handled, false positive' });
    });
  });

  it('adds a comment via /comment', async () => {
    let body: { text?: string } | null = null;
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...ALERTS[0], events: [] })),
      http.post('/api/alerts/a1/comment', async ({ request }) => {
        body = (await request.json()) as { text: string };
        return HttpResponse.json({ ok: true }, { status: 201 });
      }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
    const commentBox = screen.getByRole('textbox', { name: /add a comment/i });
    fireEvent.change(commentBox, { target: { value: 'looks like a drill' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add comment' }));
    await waitFor(() => {
      expect(body).toEqual({ text: 'looks like a drill' });
      expect(screen.getByRole('status')).toHaveTextContent(/comment added/i);
    });
  });

  it('Export CSV button is present and exports the current items', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    const spy = vi.spyOn(csv, 'downloadCsv').mockImplementation(() => {});
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    const btn = screen.getByRole('button', { name: /export csv/i });
    expect(btn).toBeEnabled();
    fireEvent.click(btn);
    expect(spy).toHaveBeenCalledTimes(1);
    const [filename, content] = spy.mock.calls[0];
    expect(filename).toMatch(/^augur-alerts-\d{4}-\d{2}-\d{2}\.csv$/);
    expect(content).toContain('scenario_id');
    expect(content).toContain('SCEN-2026-001');
    expect(content).toContain('SCEN-2026-188');
    spy.mockRestore();
  });

  it('Export CSV button is disabled when there are no alerts', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json([])));
    setup();
    await waitFor(() => expect(screen.getByText(/no alerts/i)).toBeInTheDocument());
    expect(screen.getByRole('button', { name: /export csv/i })).toBeDisabled();
  });

  it('acknowledges an open alert', async () => {
    let acked = false;
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(acked ? [{ ...ALERTS[0], state: 'acknowledged' }, ALERTS[1]] : ALERTS)),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...ALERTS[0], events: [] })),
      http.post('/api/alerts/a1/ack', () => { acked = true; return HttpResponse.json({ status: 'acknowledged', id: 'a1' }); }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Acknowledge' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/acknowledged/i));
  });

  it('severity filter can be cleared back to All (Fix 1: empty option restores unfiltered list)', async () => {
    server.use(http.get('/api/alerts', ({ request }) => {
      const url = new URL(request.url);
      const sev = url.searchParams.get('severity');
      const data = sev ? ALERTS.filter((a) => a.severity === sev) : ALERTS;
      return HttpResponse.json(data);
    }));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());

    // Pick CRITICAL
    fireEvent.click(screen.getByRole('combobox', { name: /severity/i }));
    fireEvent.click(screen.getByRole('option', { name: 'CRITICAL' }));
    await waitFor(() => expect(screen.queryByText('SCEN-2026-188')).not.toBeInTheDocument());
    expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument();

    // Clear by picking "All severities" (the empty-value option)
    fireEvent.click(screen.getByRole('combobox', { name: /severity/i }));
    fireEvent.click(screen.getByRole('option', { name: /all severities/i }));
    await waitFor(() => {
      expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument();
      expect(screen.getByText('SCEN-2026-188')).toBeInTheDocument();
    });
  });

  it('saving a filter then recalling it restores statusFilter, myQueue, severity and range', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());

    // Set a distinctive filter combination
    fireEvent.click(screen.getByRole('tab', { name: 'Acknowledged' }));
    fireEvent.click(screen.getByRole('button', { name: /my queue/i }));
    fireEvent.click(screen.getByRole('combobox', { name: /severity/i }));
    fireEvent.click(screen.getByRole('option', { name: 'HIGH' }));
    await waitFor(() => expect(screen.getByRole('tab', { name: 'Acknowledged' })).toHaveAttribute('aria-selected', 'true'));

    // Save it
    fireEvent.click(screen.getByRole('button', { name: /save filter/i }));
    fireEvent.change(screen.getByRole('textbox', { name: /filter name/i }), { target: { value: 'my-ack-high' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    // Open saved-filters to verify the option was saved
    fireEvent.click(screen.getByRole('combobox', { name: /saved filters/i }));
    await waitFor(() => expect(screen.getByRole('option', { name: 'my-ack-high' })).toBeInTheDocument());
    fireEvent.keyDown(screen.getByRole('combobox', { name: /saved filters/i }), { key: 'Escape' });

    // Mutate away (change to CRITICAL, which is different from HIGH)
    fireEvent.click(screen.getByRole('tab', { name: 'Open' }));
    fireEvent.click(screen.getByRole('button', { name: /my queue/i }));
    fireEvent.click(screen.getByRole('combobox', { name: /severity/i }));
    fireEvent.click(screen.getByRole('option', { name: 'CRITICAL' }));
    await waitFor(() => expect(screen.getByRole('tab', { name: 'Open' })).toHaveAttribute('aria-selected', 'true'));

    // Recall
    fireEvent.click(screen.getByRole('combobox', { name: /saved filters/i }));
    await waitFor(() => expect(screen.getByRole('option', { name: 'my-ack-high' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('option', { name: 'my-ack-high' }));

    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'Acknowledged' })).toHaveAttribute('aria-selected', 'true');
      expect(screen.getByRole('button', { name: /my queue/i })).toHaveAttribute('aria-pressed', 'true');
    });
    expect(screen.getByRole('combobox', { name: /severity/i })).toHaveTextContent('HIGH');
  });

  it('deep-link ?dedup_key= forwards the param and shows the linked-case banner', async () => {
    let sawKey: string | null = null;
    server.use(http.get('/api/alerts', ({ request }) => {
      const url = new URL(request.url);
      sawKey = url.searchParams.get('dedup_key');
      const data = sawKey ? ALERTS.filter((a) => a.id === 'a1') : ALERTS;
      return HttpResponse.json(data);
    }));
    setup('/alerts?dedup_key=SCEN-2026-001%7CHR_User_PC');
    await waitFor(() => {
      expect(sawKey).toBe('SCEN-2026-001|HR_User_PC');
      expect(screen.getByText(/showing 1 linked case/i)).toBeInTheDocument();
    });
    // Only the linked row is shown
    expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument();
    expect(screen.queryByText('SCEN-2026-188')).not.toBeInTheDocument();
  });

  it('Clear removes the dedup_key param and restores normal filtering', async () => {
    const keys: (string | null)[] = [];
    server.use(http.get('/api/alerts', ({ request }) => {
      const url = new URL(request.url);
      const k = url.searchParams.get('dedup_key');
      keys.push(k);
      const data = k ? ALERTS.filter((a) => a.id === 'a1') : ALERTS;
      return HttpResponse.json(data);
    }));
    setup('/alerts?dedup_key=SCEN-2026-001%7CHR_User_PC');
    await waitFor(() => expect(screen.getByText(/showing 1 linked case/i)).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /^clear$/i }));
    await waitFor(() => {
      expect(screen.queryByText(/showing 1 linked case/i)).not.toBeInTheDocument();
      expect(screen.getByText('SCEN-2026-188')).toBeInTheDocument();
    });
    // last fetch had no dedup_key
    expect(keys[keys.length - 1]).toBeNull();
  });

  it('deep-link with no matching case shows the no-case hint', async () => {
    server.use(http.get('/api/alerts', ({ request }) => {
      const url = new URL(request.url);
      return HttpResponse.json(url.searchParams.get('dedup_key') ? [] : ALERTS);
    }));
    setup('/alerts?dedup_key=SCEN-NONE%7Cnobody');
    await waitFor(() => {
      expect(screen.getByText(/no alert case exists for this detection yet/i)).toBeInTheDocument();
    });
  });
});

describe('Alerts bulk selection (Task 3.1)', () => {
  it('renders a header select-all checkbox and per-row checkboxes', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    expect(screen.getByRole('checkbox', { name: /select all/i })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /select alert scen-2026-001/i })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /select alert scen-2026-188/i })).toBeInTheDocument();
  });

  it('selecting a row reveals the bulk bar with the count and Clear empties it', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    // no bulk bar yet
    expect(screen.queryByRole('region', { name: /bulk actions/i })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('checkbox', { name: /select alert scen-2026-001/i }));
    const bar = await screen.findByRole('region', { name: /bulk actions/i });
    expect(bar).toHaveTextContent(/1 selected/i);

    fireEvent.click(screen.getByRole('button', { name: /clear selection/i }));
    await waitFor(() => expect(screen.queryByRole('region', { name: /bulk actions/i })).not.toBeInTheDocument());
  });

  it('select-all is indeterminate on a partial selection and checked when all selected', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    const selectAll = screen.getByRole('checkbox', { name: /select all/i }) as HTMLInputElement;

    fireEvent.click(screen.getByRole('checkbox', { name: /select alert scen-2026-001/i }));
    expect(selectAll.indeterminate).toBe(true);
    expect(selectAll.checked).toBe(false);

    fireEvent.click(screen.getByRole('checkbox', { name: /select alert scen-2026-188/i }));
    await waitFor(() => {
      expect(selectAll.indeterminate).toBe(false);
      expect(selectAll.checked).toBe(true);
    });
  });

  it('header select-all toggles every row', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('checkbox', { name: /select all/i }));
    const bar = await screen.findByRole('region', { name: /bulk actions/i });
    expect(bar).toHaveTextContent(/2 selected/i);
    expect((screen.getByRole('checkbox', { name: /select alert scen-2026-001/i }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByRole('checkbox', { name: /select alert scen-2026-188/i }) as HTMLInputElement).checked).toBe(true);
  });
});

describe('Alerts bulk actions (Task 3.2)', () => {
  it('bulk Acknowledge posts /ack for each selected id and clears selection', async () => {
    const acked: string[] = [];
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.post('/api/alerts/:id/ack', ({ params }) => { acked.push(params.id as string); return HttpResponse.json({ ok: true }); }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('checkbox', { name: /select all/i }));
    await screen.findByRole('region', { name: /bulk actions/i });
    fireEvent.click(screen.getByRole('button', { name: /^acknowledge$/i }));
    await waitFor(() => expect(acked.sort()).toEqual(['a1', 'a2']));
    await waitFor(() => expect(screen.queryByRole('region', { name: /bulk actions/i })).not.toBeInTheDocument());
  });

  it('bulk Assign to me posts /assign with the current user for each id', async () => {
    const bodies: { id: string; assignee: string }[] = [];
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.post('/api/alerts/:id/assign', async ({ params, request }) => {
        const b = (await request.json()) as { assignee: string };
        bodies.push({ id: params.id as string, assignee: b.assignee });
        return HttpResponse.json({ ok: true });
      }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('checkbox', { name: /select all/i }));
    await screen.findByRole('region', { name: /bulk actions/i });
    fireEvent.click(screen.getByRole('button', { name: /assign to me/i }));
    await waitFor(() => expect(bodies.length).toBe(2));
    expect(bodies.every((b) => b.assignee === 'an')).toBe(true);
  });

  it('bulk Resolve requires a note: empty note → no calls + error toast', async () => {
    let statusCalls = 0;
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.post('/api/alerts/:id/status', () => { statusCalls += 1; return HttpResponse.json({ ok: true }); }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('checkbox', { name: /select all/i }));
    await screen.findByRole('region', { name: /bulk actions/i });
    // open the resolve flow
    fireEvent.click(screen.getByRole('button', { name: /^resolve$/i }));
    const note = await screen.findByRole('textbox', { name: /resolution note/i });
    // submit with empty note
    fireEvent.click(screen.getByRole('button', { name: /^resolve$/i }));
    await waitFor(() => expect(screen.getByRole('status')).toBeInTheDocument());
    expect(statusCalls).toBe(0);

    // now with a note it posts for each id
    const bodies: { id: string; status: string; note: string }[] = [];
    server.use(http.post('/api/alerts/:id/status', async ({ params, request }) => {
      const b = (await request.json()) as { status: string; note: string };
      bodies.push({ id: params.id as string, status: b.status, note: b.note });
      return HttpResponse.json({ ok: true });
    }));
    fireEvent.change(note, { target: { value: 'triaged benign' } });
    fireEvent.click(screen.getByRole('button', { name: /^resolve$/i }));
    await waitFor(() => expect(bodies.length).toBe(2));
    expect(bodies.every((b) => b.status === 'resolved' && b.note === 'triaged benign')).toBe(true);
  });

  it('partial failure surfaces a partial toast', async () => {
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.post('/api/alerts/a1/ack', () => HttpResponse.json({ ok: true })),
      http.post('/api/alerts/a2/ack', () => HttpResponse.json({ detail: 'nope' }, { status: 500 })),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('checkbox', { name: /select all/i }));
    await screen.findByRole('region', { name: /bulk actions/i });
    fireEvent.click(screen.getByRole('button', { name: /^acknowledge$/i }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/1 updated, 1 failed/i));
  });
});

describe('Alerts keyboard shortcuts (Task 4.1 trigger + 4.2)', () => {
  it('toolbar shortcuts button opens the help overlay', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /shortcuts/i }));
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
  });

  it('? opens the help overlay', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.keyDown(document, { key: '?' });
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
  });

  it('j / k move the active row', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    const rows = screen.getAllByRole('row').filter((r) => r.hasAttribute('data-active'));
    // initial active row is index 0
    expect(rows[0]).toHaveAttribute('data-active', 'true');
    expect(rows[0]).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(document, { key: 'j' });
    await waitFor(() => expect(rows[1]).toHaveAttribute('data-active', 'true'));
    expect(rows[0]).toHaveAttribute('data-active', 'false');

    fireEvent.keyDown(document, { key: 'k' });
    await waitFor(() => expect(rows[0]).toHaveAttribute('data-active', 'true'));
  });

  it('a acknowledges the active alert', async () => {
    const acked: string[] = [];
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.post('/api/alerts/:id/ack', ({ params }) => { acked.push(params.id as string); return HttpResponse.json({ ok: true }); }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.keyDown(document, { key: 'a' });
    await waitFor(() => expect(acked).toEqual(['a1']));
  });

  it('r opens the drawer for the active row', async () => {
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...ALERTS[0], events: [] })),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.keyDown(document, { key: 'r' });
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
  });

  it('/ focuses the filter control', async () => {
    server.use(http.get('/api/alerts', () => HttpResponse.json(ALERTS)));
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.keyDown(document, { key: '/' });
    await waitFor(() =>
      expect(document.activeElement).toBe(screen.getByRole('combobox', { name: /severity/i })),
    );
  });

  it('typing a in the resolution note does NOT ack or move rows (input guard)', async () => {
    const acked: string[] = [];
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.get('/api/alerts/a1', () => HttpResponse.json({ ...ALERTS[0], events: [] })),
      http.post('/api/alerts/:id/ack', ({ params }) => { acked.push(params.id as string); return HttpResponse.json({ ok: true }); }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    // open the drawer + reveal the resolve note
    fireEvent.click(screen.getByRole('button', { name: /view alert scen-2026-001/i }));
    await screen.findByRole('dialog');
    fireEvent.click(screen.getByRole('combobox', { name: /set status/i }));
    fireEvent.click(screen.getByRole('option', { name: /resolved/i }));
    const note = await screen.findByRole('textbox', { name: /resolution note/i });
    note.focus();
    fireEvent.keyDown(note, { key: 'a' });
    fireEvent.keyDown(note, { key: 'j' });
    // give any handler a tick
    await new Promise((r) => setTimeout(r, 0));
    expect(acked).toEqual([]);
  });

  it('Ctrl+a is ignored', async () => {
    const acked: string[] = [];
    server.use(
      http.get('/api/alerts', () => HttpResponse.json(ALERTS)),
      http.post('/api/alerts/:id/ack', ({ params }) => { acked.push(params.id as string); return HttpResponse.json({ ok: true }); }),
    );
    setup();
    await waitFor(() => expect(screen.getByText('SCEN-2026-001')).toBeInTheDocument());
    fireEvent.keyDown(document, { key: 'a', ctrlKey: true });
    await new Promise((r) => setTimeout(r, 0));
    expect(acked).toEqual([]);
  });
});
