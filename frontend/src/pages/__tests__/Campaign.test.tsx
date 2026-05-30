import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Campaign from '../Campaign';
import * as api from '../../lib/api';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k) }),
}));

const HONESTY =
  'Deterministic replay of the scenario library through the engine — detection by construction, not a live-network claim.';

const CAMPAIGN_RESPONSE = {
  definition: { selector: 'all', selector_value: null, min_proximity: 1.0, scenario_count: 2 },
  honesty: HONESTY,
  rows: [
    {
      scenario_id: 'SCEN-WIN-001', name: 'Pass-the-Hash', tactic: 'TA0006', technique: 'T1550',
      os_family: 'windows', host: 'DC01', status: 'detected', detected: true,
      proximity: 1.0, matched_steps: 3, total_steps: 3,
      feed_summary: { total_events: 150, baseline_events: 100, injected_events: 50 },
      note: 'Detected cleanly on DC01',
    },
    {
      scenario_id: 'SCEN-MAC-001', name: 'macOS persistence', tactic: 'TA0003', technique: 'T1543',
      os_family: 'macos', host: null, status: 'no_eligible_host', detected: false,
      proximity: 0, matched_steps: 0, total_steps: 4, feed_summary: null,
      note: 'no eligible host in current topology',
    },
  ],
  aggregate: {
    runnable: 1, detected: 1, missed: 0, no_eligible_host: 1, errors: 0, pct_detected: 1.0,
    gaps_by_tactic: {}, no_eligible_host_scenarios: ['SCEN-MAC-001'],
  },
};

// Keep a PAYLOAD alias for backward-compat with older test assertions
const PAYLOAD = CAMPAIGN_RESPONSE;

function setup() {
  return render(
    <MemoryRouter>
      <Campaign />
    </MemoryRouter>
  );
}

describe('Campaign', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('auto-fetches on mount and renders rows, % detected, status badge, and honesty banner', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    setup();

    // scenario_id renders (waits out the auto-fetch)
    await waitFor(() => expect(screen.getByText('SCEN-WIN-001')).toBeInTheDocument());
    // SCEN-MAC-001 appears both as a table row and in the no-eligible-host gap list.
    expect(screen.getAllByText(/SCEN-MAC-001/).length).toBeGreaterThanOrEqual(1);

    // % detected aggregate header (interpolated key from the mocked t)
    expect(screen.getByText(/campaign\.pctDetected .*"pct":100/)).toBeInTheDocument();

    // status badges (detected + no_eligible_host)
    expect(screen.getByText('campaign.status.detected')).toBeInTheDocument();
    expect(screen.getByText('campaign.status.no_eligible_host')).toBeInTheDocument();

    // persistent honesty banner
    expect(screen.getByText(HONESTY)).toBeInTheDocument();
  });

  it('shows the empty state when there are no rows', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue({
      ...PAYLOAD,
      rows: [],
      aggregate: { ...PAYLOAD.aggregate, detected: 0, no_eligible_host: 0, pct_detected: 0, no_eligible_host_scenarios: [] },
    } as never);
    setup();
    await waitFor(() => expect(screen.getByText('campaign.empty')).toBeInTheDocument());
  });

  it('opens the drawer showing feed_summary + note (neither shown in the row)', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(CAMPAIGN_RESPONSE as never);
    setup();
    const row = CAMPAIGN_RESPONSE.rows[0];
    const btn = await screen.findByRole('button', {
      name: new RegExp(`campaign\\.detail\\.open.*${row.name}`, 'i'),
    });
    fireEvent.click(btn);
    const dlg = screen.getByRole('dialog');
    if (row.feed_summary) {
      expect(within(dlg).getByText(String(row.feed_summary.injected_events))).toBeInTheDocument();
    }
    if (row.note) expect(within(dlg).getByText(row.note)).toBeInTheDocument();
  });

  it('opens on load from ?scenario= deep-link', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(CAMPAIGN_RESPONSE as never);
    const id = CAMPAIGN_RESPONSE.rows[0].scenario_id;
    render(
      <MemoryRouter initialEntries={[`/campaign?scenario=${id}`]}>
        <Campaign />
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
  });
});

