import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import Handover from '../Handover';
import * as api from '../../lib/api';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k) }),
}));

const PAYLOAD = {
  window: { from: '2026-01-01T09:00:00+00:00', to: '2026-01-01T18:00:00+00:00' },
  meta: { min_proximity: 0.3, basis: 'corpus-windowed', deterministic: true },
  detections: {
    new: [{ scenario_id: 'SCEN-WIN-009', name: 'New thing', severity: 'HIGH', proximity_prior: null, proximity_current: 0.9, proximity_delta: 0.9, band_prior: null, band_current: 'HIGH', band_changed: true, affected_hosts: ['H1'] }],
    escalated: [{ scenario_id: 'SCEN-WIN-001', name: 'Esc thing', severity: 'CRITICAL', proximity_prior: 0.6, proximity_current: 1.0, proximity_delta: 0.4, band_prior: 'WATCH', band_current: 'CONFIRMED', band_changed: true, affected_hosts: ['H2'] }],
    decayed: [], gone: [], unchanged_count: 3,
  },
  host_risk: {
    entered: [{ hostname: 'H1', zone: 'DMZ', criticality: 'HIGH', score_prior: 0, score_current: 4, score_delta: 4, band_prior: 'CLEAR', band_current: 'HIGH' }],
    left: [], escalated: [], deescalated: [],
  },
  summary: { counts: { new: 1, escalated: 1, decayed: 0, gone: 0, unchanged: 3, hosts_entered: 1, hosts_left: 0, hosts_escalated: 0, hosts_deescalated: 0 } },
};

describe('Handover', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('renders new + escalated sections and host movement from the payload', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    render(<Handover />);
    await waitFor(() => expect(screen.getByText('SCEN-WIN-009')).toBeInTheDocument());
    expect(screen.getByText('SCEN-WIN-001')).toBeInTheDocument();
    expect(screen.getByText('handover.sections.new')).toBeInTheDocument();
    expect(screen.getByText('handover.sections.escalated')).toBeInTheDocument();
    expect(screen.getByText('H1')).toBeInTheDocument();
  });

  it('shows the empty message when there are no board changes', async () => {
    const empty = { ...PAYLOAD, detections: { new: [], escalated: [], decayed: [], gone: [], unchanged_count: 5 }, host_risk: { entered: [], left: [], escalated: [], deescalated: [] }, summary: { counts: { new: 0, escalated: 0, decayed: 0, gone: 0, unchanged: 5, hosts_entered: 0, hosts_left: 0, hosts_escalated: 0, hosts_deescalated: 0 } } };
    vi.spyOn(api, 'apiGet').mockResolvedValue(empty as never);
    render(<Handover />);
    await waitFor(() => expect(screen.getByText('handover.empty')).toBeInTheDocument());
  });
});
