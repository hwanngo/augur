import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Stack from './Stack';
import * as api from '../lib/api';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k),
  }),
}));

const PROCESS_RESP = {
  dimension: 'process',
  params: { max_count: 5, limit: 100 },
  summary: { total_values: 2, rare_values: 1, returned: 1, truncated: false, honesty_note: 'LEAD not verdict' },
  rows: [
    {
      value: 'rundll32.exe', occurrences: 1, host_count: 1, single_host: true, unique: true,
      first_seen: '2026-01-01T10:00:00+00:00', last_seen: '2026-01-01T10:00:00+00:00',
      hosts: [{ hostname: 'FIN-CFO-PC', zone: 'Finance', criticality: 'CRITICAL', count: 1 }],
      samples: [{ host: 'FIN-CFO-PC', timestamp: '2026-01-01T10:00:00+00:00', command: 'rundll32.exe ...' }],
      hosts_truncated: false, samples_truncated: false,
    },
  ],
};

/** Row with hosts_truncated=true, host_count=30, only 4 hosts returned from backend */
const TRUNCATED_HOSTS_RESP = {
  dimension: 'process',
  params: { max_count: 5, limit: 100 },
  summary: { total_values: 50, rare_values: 30, returned: 1, truncated: false, honesty_note: 'LEAD not verdict' },
  rows: [
    {
      value: 'suspicious.exe', occurrences: 2, host_count: 30, single_host: false, unique: false,
      first_seen: '2026-01-01T10:00:00+00:00', last_seen: '2026-01-01T10:05:00+00:00',
      hosts: [
        { hostname: 'HOST-A', zone: 'Corp', criticality: 'HIGH', count: 1 },
        { hostname: 'HOST-B', zone: 'Corp', criticality: 'HIGH', count: 1 },
        { hostname: 'HOST-C', zone: 'Corp', criticality: 'LOW', count: 1 },
        { hostname: 'HOST-D', zone: 'Corp', criticality: 'LOW', count: 1 },
      ],
      samples: [{ host: 'HOST-A', timestamp: '2026-01-01T10:00:00+00:00', command: 'suspicious.exe --run' }],
      hosts_truncated: true, samples_truncated: false,
    },
  ],
};

const PARENT_RESP = {
  ...PROCESS_RESP, dimension: 'parent_child',
  rows: [{ ...PROCESS_RESP.rows[0], value: 'winword.exe → rundll32.exe' }],
};

const EMPTY_RESP = {
  dimension: 'process',
  params: { max_count: 5, limit: 100 },
  summary: { total_values: 0, rare_values: 0, returned: 0, truncated: false, honesty_note: 'LEAD not verdict' },
  rows: [],
};

function renderAt(path = '/stack') {
  return render(<MemoryRouter initialEntries={[path]}><Stack /></MemoryRouter>);
}

describe('Stack — rarity page', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('loads process dimension on mount and renders the rarest table + criticality chip', async () => {
    const spy = vi.spyOn(api, 'apiGet').mockResolvedValue(PROCESS_RESP as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('rundll32.exe')).toBeInTheDocument());
    expect(spy).toHaveBeenCalledWith(expect.stringContaining('dimension=process'));
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('FIN-CFO-PC')).toBeInTheDocument();
  });

  it('renders the persistent honesty panel', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PROCESS_RESP as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('stack.honesty')).toBeInTheDocument());
  });

  it('deep-link ?dimension=parent_child loads that dimension on mount', async () => {
    const spy = vi.spyOn(api, 'apiGet').mockResolvedValue(PARENT_RESP as never);
    renderAt('/stack?dimension=parent_child');
    await waitFor(() => expect(screen.getByText('winword.exe → rundll32.exe')).toBeInTheDocument());
    expect(spy).toHaveBeenCalledWith(expect.stringContaining('dimension=parent_child'));
  });

  it('switching the dimension refetches', async () => {
    const spy = vi.spyOn(api, 'apiGet')
      .mockResolvedValueOnce(PROCESS_RESP as never)
      .mockResolvedValueOnce(PARENT_RESP as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('rundll32.exe')).toBeInTheDocument());
    // open the dimension Dropdown and pick parent_child
    fireEvent.click(screen.getByRole('combobox'));
    fireEvent.click(screen.getByText('stack.dim.parent_child'));
    await waitFor(() =>
      expect(spy).toHaveBeenCalledWith(expect.stringContaining('dimension=parent_child')));
  });

  it('CSV export button appears when there are rows', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PROCESS_RESP as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('stack.export')).toBeInTheDocument());
  });

  it('empty state: renders stack.empty message and hides the CSV export button', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(EMPTY_RESP as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('stack.empty')).toBeInTheDocument());
    expect(screen.queryByText('stack.export')).not.toBeInTheDocument();
  });

  it('truncation indicator: row with hosts_truncated=true and host_count=30 shows "+26 more" chip', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(TRUNCATED_HOSTS_RESP as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('suspicious.exe')).toBeInTheDocument());
    // 4 hosts shown, host_count=30 → "+26 more"
    expect(screen.getByText(/stack\.cols\.moreHosts.*"n":26/)).toBeInTheDocument();
  });

  it('row drill is keyboard-operable: pressing Enter on a row opens the DetailDrawer', async () => {
    vi.spyOn(api, 'apiGet').mockResolvedValue(PROCESS_RESP as never);
    renderAt();
    await waitFor(() => expect(screen.getByText('rundll32.exe')).toBeInTheDocument());
    // t() mock renders "stack.cols.inspectRow {"value":"rundll32.exe"}"
    const row = screen.getByRole('button', { name: /stack\.cols\.inspectRow/ });
    row.focus();
    fireEvent.keyDown(row, { key: 'Enter' });
    await waitFor(() => expect(screen.getByText('stack.drawer.hosts')).toBeInTheDocument());
  });
});
