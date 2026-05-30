import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import TriagePanel from '../TriagePanel';
import * as api from '../../lib/api';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string) => k }),
}));

const PAYLOAD = {
  window: { from: '2026-06-01T08:00:00+00:00', to: '2026-06-01T18:00:00+00:00' },
  meta: { basis: 'alert-lifecycle-wallclock', deterministic: true },
  triage: {
    new_alerts: [{ alert_id: 'a1', scenario_id: 'SCEN-WIN-001', scenario_name: 'Cred Theft',
                   severity: 'CRITICAL', assignee: '', status: 'open', ts: '2026-06-01T10:00:00+00:00', ts_field: 'created_at' }],
    assigned: [{ alert_id: 'a2', scenario_id: 'SCEN-LNX-001', scenario_name: 'Cron Persist',
                 severity: 'HIGH', assignee: 'alice', status: 'in_progress', ts: '2026-06-01T11:00:00+00:00', ts_field: 'assigned_at' }],
    resolved: [], reopened: [],
  },
  summary: { counts: { new_alerts: 1, assigned: 1, resolved: 0, reopened: 0 } },
};

describe('TriagePanel', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('renders new + assigned sections from the payload', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    render(<TriagePanel />);
    await waitFor(() => expect(screen.getByText('SCEN-WIN-001')).toBeInTheDocument());
    expect(screen.getByText('SCEN-LNX-001')).toBeInTheDocument();
    expect(screen.getByText('handover.triage.sections.newAlerts')).toBeInTheDocument();
    expect(screen.getByText('handover.triage.sections.assigned')).toBeInTheDocument();
    expect(screen.getByText('alice')).toBeInTheDocument();
  });

  it('shows the no-data empty state when window.from is null', async () => {
    const empty = { ...PAYLOAD, window: { from: null, to: null },
      triage: { new_alerts: [], assigned: [], resolved: [], reopened: [] },
      summary: { counts: { new_alerts: 0, assigned: 0, resolved: 0, reopened: 0 } } };
    vi.spyOn(api, 'apiGet').mockResolvedValue(empty as never);
    render(<TriagePanel />);
    await waitFor(() => expect(screen.getByText('handover.triage.emptyNoData')).toBeInTheDocument());
  });
});
