import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import TimeRangePicker, { type TimeRange } from '../TimeRangePicker';

const ALL: TimeRange = { preset: 'all', from: null, to: null };

function setup(value: TimeRange = ALL) {
  const onChange = vi.fn();
  render(<TimeRangePicker value={value} onChange={onChange} label="Detections time range" />);
  const trigger = screen.getByRole('combobox', { name: 'Detections time range' });
  const pick = (name: RegExp) => {
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('option', { name }));
  };
  return { onChange: onChange as ReturnType<typeof vi.fn>, trigger, pick };
}

describe('TimeRangePicker', () => {
  it('exposes a combobox with a distinct aria-label', () => {
    setup();
    expect(screen.getByRole('combobox', { name: 'Detections time range' })).toBeInTheDocument();
  });

  it('selecting Last 24h emits absolute ISO from/to (not the literal token)', () => {
    const { onChange, pick } = setup();
    const before = Date.now();
    pick(/last 24 hours/i);
    const after = Date.now();

    expect(onChange).toHaveBeenCalledTimes(1);
    const r: TimeRange = onChange.mock.calls[0][0];
    expect(r.preset).toBe('24h');
    expect(r.from).not.toBe('24h'); // not the literal token

    const from = new Date(r.from as string);
    const to = new Date(r.to as string);
    expect(Number.isNaN(from.getTime())).toBe(false);
    expect(Number.isNaN(to.getTime())).toBe(false);
    expect(from.getTime()).toBeLessThan(to.getTime());
    // 24h window, with `to` ~ now
    expect(to.getTime() - from.getTime()).toBe(24 * 60 * 60 * 1000);
    expect(to.getTime()).toBeGreaterThanOrEqual(before);
    expect(to.getTime()).toBeLessThanOrEqual(after);
  });

  it('selecting Last 7d emits a 7-day window', () => {
    const { onChange, pick } = setup();
    pick(/last 7 days/i);
    const r: TimeRange = onChange.mock.calls[0][0];
    expect(r.preset).toBe('7d');
    const span = new Date(r.to as string).getTime() - new Date(r.from as string).getTime();
    expect(span).toBe(7 * 24 * 60 * 60 * 1000);
  });

  it('selecting Last 30d emits a 30-day window', () => {
    const { onChange, pick } = setup();
    pick(/last 30 days/i);
    const r: TimeRange = onChange.mock.calls[0][0];
    expect(r.preset).toBe('30d');
    const span = new Date(r.to as string).getTime() - new Date(r.from as string).getTime();
    expect(span).toBe(30 * 24 * 60 * 60 * 1000);
  });

  it('selecting All time emits null from/to', () => {
    const { onChange, pick } = setup({ preset: '24h', from: 'x', to: 'y' });
    pick(/all time/i);
    expect(onChange).toHaveBeenCalledWith({ preset: 'all', from: null, to: null });
  });

  it('Custom reveals two datetime-local inputs', () => {
    const { trigger } = setup();
    expect(screen.queryByLabelText('From')).not.toBeInTheDocument();

    // Trigger the custom option to fire onChange, then render in custom mode
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('option', { name: /custom/i }));
    render(
      <TimeRangePicker
        value={{ preset: 'custom', from: null, to: null }}
        onChange={() => {}}
        label="Detections custom"
      />
    );
    const fromInput = screen.getByLabelText('From') as HTMLInputElement;
    const toInput = screen.getByLabelText('To') as HTMLInputElement;
    expect(fromInput.type).toBe('datetime-local');
    expect(toInput.type).toBe('datetime-local');
  });

  it('editing a custom datetime emits an absolute ISO bound', () => {
    const onChange = vi.fn();
    render(
      <TimeRangePicker
        value={{ preset: 'custom', from: null, to: null }}
        onChange={onChange}
        label="Detections time range"
      />
    );
    const fromInput = screen.getByLabelText('From');
    fireEvent.change(fromInput, { target: { value: '2026-05-01T00:00' } });

    expect(onChange).toHaveBeenCalled();
    const last: TimeRange = onChange.mock.calls[onChange.mock.calls.length - 1][0];
    expect(last.preset).toBe('custom');
    expect(last.from).not.toBeNull();
    expect(Number.isNaN(new Date(last.from as string).getTime())).toBe(false);
  });
});
