import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Intel from './Intel';
import * as api from '../lib/api';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k),
  }),
}));

const EXTRACT = {
  summary: { extracted_total: 3, matchable_count: 2, unmatchable_count: 1, truncated: false,
             honesty_note: 'pattern-matching, not AI' },
  matchable: [
    { type: 'technique', value: 'T1059.001', category: 'tactic', confidence: 'high', matchable: true },
    { type: 'process_name', value: 'rundll32.exe', category: 'host', confidence: 'medium', matchable: true },
  ],
  unmatchable: [
    { type: 'ipv4', value: '192.0.2.9', category: 'network', confidence: 'high', matchable: false,
      defanged_from: '192[.]0[.]2[.]9', reason: 'the corpus carries no network indicators' },
  ],
};

describe('Intel — paste-report extraction', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('extract renders the matchable / unmatchable split + honesty', async () => {
    const spy = vi.spyOn(api, 'apiPost').mockResolvedValue(EXTRACT as never);
    render(<Intel />);
    fireEvent.click(screen.getByText('intel.mode.paste'));
    fireEvent.change(screen.getByLabelText('intel.extract.inputLabel'),
                     { target: { value: 'T1059.001 rundll32.exe 192[.]0[.]2[.]9' } });
    fireEvent.click(screen.getByText('intel.extract.run'));
    await waitFor(() => expect(screen.getByText('T1059.001')).toBeInTheDocument());
    expect(spy).toHaveBeenCalledWith('/api/ioc_extract', { text: 'T1059.001 rundll32.exe 192[.]0[.]2[.]9' });
    expect(screen.getByText('rundll32.exe')).toBeInTheDocument();
    expect(screen.getByText('192.0.2.9')).toBeInTheDocument();
    expect(screen.getByText(/intel.extract.honesty/)).toBeInTheDocument();
    expect(screen.getByText(/intel.extract.matchableSection.*"count":2/)).toBeInTheDocument();
    expect(screen.getByText(/intel.extract.unmatchableSection.*"count":1/)).toBeInTheDocument();
  });

  it('push-to-watchlist populates the manual textarea with only matchable type:value lines', async () => {
    vi.spyOn(api, 'apiPost').mockResolvedValue(EXTRACT as never);
    render(<Intel />);
    fireEvent.click(screen.getByText('intel.mode.paste'));
    fireEvent.change(screen.getByLabelText('intel.extract.inputLabel'), { target: { value: 'report' } });
    fireEvent.click(screen.getByText('intel.extract.run'));
    await waitFor(() => expect(screen.getByText('intel.extract.push')).toBeInTheDocument());
    fireEvent.click(screen.getByText('intel.extract.push'));
    // pushToWatchlist switches back to manual mode; the manual textarea now holds the lines.
    const ta = await screen.findByLabelText('intel.inputLabel');
    expect((ta as HTMLTextAreaElement).value).toBe('technique:T1059.001\nprocess_name:rundll32.exe');
  });

  it('manual mode still renders the existing watchlist input', () => {
    render(<Intel />);
    expect(screen.getByLabelText('intel.inputLabel')).toBeInTheDocument();
    expect(screen.getByText('intel.run')).toBeInTheDocument();
  });

  it('extraction error state: renders the role=alert error panel when apiPost rejects', async () => {
    vi.spyOn(api, 'apiPost').mockRejectedValue(new Error('boom'));
    render(<Intel />);
    fireEvent.click(screen.getByText('intel.mode.paste'));
    fireEvent.change(screen.getByLabelText('intel.extract.inputLabel'),
                     { target: { value: 'some report text' } });
    fireEvent.click(screen.getByText('intel.extract.run'));
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    // error panel should be visible, not swallowed
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('dedup: pushing matchable to watchlist skips entries already present in the textarea', async () => {
    vi.spyOn(api, 'apiPost').mockResolvedValue(EXTRACT as never);
    render(<Intel />);
    // Pre-populate the manual watchlist with one of the matchable lines
    fireEvent.change(screen.getByLabelText('intel.inputLabel'),
                     { target: { value: 'technique:T1059.001' } });
    // Switch to paste mode and extract
    fireEvent.click(screen.getByText('intel.mode.paste'));
    fireEvent.change(screen.getByLabelText('intel.extract.inputLabel'),
                     { target: { value: 'some report' } });
    fireEvent.click(screen.getByText('intel.extract.run'));
    await waitFor(() => expect(screen.getByText('intel.extract.push')).toBeInTheDocument());
    fireEvent.click(screen.getByText('intel.extract.push'));
    // pushToWatchlist switches back to manual mode; check the textarea
    const ta = await screen.findByLabelText('intel.inputLabel');
    const lines = (ta as HTMLTextAreaElement).value.split('\n').filter(Boolean);
    // process_name:rundll32.exe should be present exactly once
    expect(lines.filter((l) => l === 'process_name:rundll32.exe')).toHaveLength(1);
    // technique:T1059.001 should NOT be duplicated (already was in watchlist)
    expect(lines.filter((l) => l === 'technique:T1059.001')).toHaveLength(1);
  });
});
