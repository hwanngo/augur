import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Timeline from '../Timeline';
import * as api from '../../lib/api';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k) }),
}));

const NOTE = 'Context events are the surrounding telemetry on the affected hosts — not a causal claim.';
const PAYLOAD = {
  scenario_id: 'SCEN-WIN-001',
  name: 'Pass-the-Hash',
  severity: 'CRITICAL',
  hosts: ['WS01'],
  band: { from: '2024-01-01T00:00:00Z', to: '2024-01-01T00:05:00Z', pad_seconds: 300 },
  matched_count: 2,
  context_shown: 1,
  context_total: 1,
  context_truncated: false,
  honesty_note: NOTE,
  rows: [
    { timestamp: '2024-01-01T00:00:01Z', host: 'WS01', kind: 'matched_step', event_kind: 'process_create',
      label: 'cmd.exe spawned', step_id: 1, step_name: 'Spawn', element_id: 'p1' },
    { timestamp: '2024-01-01T00:00:02Z', host: 'WS01', kind: 'context', event_kind: 'process_create',
      label: 'explorer.exe', step_id: null, step_name: null, element_id: 'p2' },
    { timestamp: '2024-01-01T00:00:03Z', host: 'WS01', kind: 'matched_step', event_kind: 'process_create',
      label: 'lsass access', step_id: 2, step_name: 'Dump', element_id: 'p3' },
  ],
};

function renderAt(search = '?scenario_id=SCEN-WIN-001') {
  return render(
    <MemoryRouter initialEntries={[`/timeline${search}`]}>
      <Timeline />
    </MemoryRouter>
  );
}

describe('Timeline', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('renders matched steps, a context row, and the honesty note', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PAYLOAD as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('Pass-the-Hash')).toBeInTheDocument());
    // matched step_name (rendered as "timeline.matchedStep {id} · {step_name}")
    expect(screen.getByText(/Spawn/)).toBeInTheDocument();
    expect(screen.getByText(/Dump/)).toBeInTheDocument();
    // context row label
    expect(screen.getByText('explorer.exe')).toBeInTheDocument();
    // honesty note verbatim
    expect(screen.getByText(NOTE)).toBeInTheDocument();
  });

  it('shows the empty state when there are no rows', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue({ ...PAYLOAD, rows: [] } as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('timeline.empty')).toBeInTheDocument());
  });

  it('shows a loading state before data resolves', () => {
    vi.spyOn(api, 'apiGet').mockReturnValue(new Promise(() => {}) as never);
    renderAt();
    expect(screen.getByText('timeline.loading')).toBeInTheDocument();
  });
});
