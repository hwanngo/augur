import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Intel from '../Intel';
import * as api from '../../lib/api';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k) }),
}));

const NOTE = 'Lexical IOC overlay over ingested events and the scenario library — not a live blocklist.';
const RESULT = {
  summary: { iocs_total: 2, iocs_matched: 2, hosts_touched: 1, honesty_note: NOTE },
  iocs: [
    {
      type: 'command', value: 'mimikatz', target: 'event', matched: true, hit_count: 1, truncated: false,
      hits: [{ host: 'WIN-DC01', timestamp: '2026-05-31T10:15:42Z', label: 'Process Create',
               matched_field: 'command_line', snippet: 'C:\\tools\\mimikatz.exe sekurlsa::logonpasswords' }],
    },
    {
      type: 'technique', value: 'T1003.001', target: 'scenario', matched: true, hit_count: 1, truncated: false,
      covered: true, covered_scenarios: ['SCEN-WIN-001'],
      hits: [{ scenario_id: 'SCEN-WIN-001', name: 'LSASS dump', proximity: 1, affected_hosts: ['WIN-DC01'] }],
    },
  ],
  hosts: [{ hostname: 'WIN-DC01', zone: 'Active_Directory', criticality: 'CRITICAL', ioc_count: 2, types: ['command', 'technique'] }],
};

function setup() {
  render(<Intel />);
  fireEvent.change(screen.getByLabelText('intel.inputLabel'), {
    target: { value: 'command:mimikatz\ntechnique:T1003.001' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'intel.run' }));
}

describe('Intel page', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('shows no results before running', () => {
    vi.spyOn(api, 'apiPost').mockResolvedValue(RESULT as never);
    render(<Intel />);
    expect(screen.queryByText(NOTE)).not.toBeInTheDocument();
    expect(screen.queryByText('LSASS dump')).not.toBeInTheDocument();
  });

  it('runs an IOC match and renders event hits, technique coverage, hosts rollup, and the honesty note', async () => {
    vi.spyOn(api, 'apiPost').mockResolvedValue(RESULT as never);
    setup();

    // Event IOC value + its hit host
    expect(await screen.findByText('command:mimikatz')).toBeInTheDocument();
    expect(screen.getAllByText('WIN-DC01').length).toBeGreaterThan(0);

    // Technique coverage block
    expect(screen.getByText('intel.techniqueSection')).toBeInTheDocument();
    expect(screen.getByText('LSASS dump')).toBeInTheDocument();

    // Hosts rollup + honesty note
    expect(screen.getByText('intel.hostsSection')).toBeInTheDocument();
    expect(screen.getByText(NOTE)).toBeInTheDocument();
  });

  it('surfaces a 422 ApiError message', async () => {
    vi.spyOn(api, 'apiPost').mockRejectedValue(new api.ApiError(422, 'unsupported IOC type: hash'));
    setup();
    await waitFor(() => expect(screen.getByText('unsupported IOC type: hash')).toBeInTheDocument());
  });
});
