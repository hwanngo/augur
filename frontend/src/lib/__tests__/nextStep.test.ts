import { describe, it, expect } from 'vitest';
import { formatCriteria, formatTemporal, formatStall, type Stall } from '../nextStep';

describe('formatCriteria', () => {
  it('renders a literal field', () => {
    expect(formatCriteria({ Node_Type: 'Process', ProcessName: 'rundll32.exe' }))
      .toContain('ProcessName = rundll32.exe');
  });
  it('renders an {in} operator as a list', () => {
    expect(formatCriteria({ Node_Type: 'Process', ProcessName: { in: ['a.exe', 'b.exe'] } }))
      .toContain('ProcessName in [a.exe, b.exe]');
  });
  it('renders regex / exists operators and skips Node_Type', () => {
    const out = formatCriteria({ Node_Type: 'File', Path: { regex: '\\\\Temp\\\\' }, IsSigned: { exists: false } });
    expect(out).not.toContain('Node_Type');
    expect(out).toContain('Path ~ ');
    expect(out).toContain('IsSigned');
  });
  it('returns empty string for undefined criteria', () => {
    expect(formatCriteria(undefined)).toBe('');
  });
});

describe('formatTemporal', () => {
  it('returns null for a null temporal', () => {
    expect(formatTemporal(null)).toBeNull();
  });
  it('renders window + same-host scope', () => {
    expect(formatTemporal({ previous_step: 1, link_scope: 'same_host',
      min_time_delta_seconds: 0, max_time_delta_seconds: 120 }))
      .toMatch(/within .*120s.*same host/i);
  });
});

describe('formatStall', () => {
  it('temporal overshoot mentions host, delta and window', () => {
    const s: Stall = { kind: 'temporal', step_id: 3, host: 'PC1', delta_seconds: 300, window_seconds: 120 };
    expect(formatStall(s)).toMatch(/PC1/);
    expect(formatStall(s)).toMatch(/300/);
    expect(formatStall(s)).toMatch(/120/);
  });
  it('no_candidate mentions the step name', () => {
    expect(formatStall({ kind: 'no_candidate', step_id: 2, step_name: 'LSASS access' }))
      .toMatch(/no event/i);
    expect(formatStall({ kind: 'no_candidate', step_id: 2, step_name: 'LSASS access' }))
      .toMatch(/LSASS access/);
  });
  it('spatial mentions the zone', () => {
    expect(formatStall({ kind: 'spatial', step_id: 2, host: 'PC1', zone: 'DMZ', applicable_zones: ['Server'] }))
      .toMatch(/DMZ/);
  });
  it('link mentions the required scope', () => {
    expect(formatStall({ kind: 'link', step_id: 2, host: 'PC1', link_scope: 'same_host' }))
      .toMatch(/same/i);
  });
  it('rounds a fractional delta', () => {
    const s: Stall = { kind: 'temporal', step_id: 3, host: 'PC1', delta_seconds: 300.7, window_seconds: 120 };
    expect(formatStall(s)).toMatch(/301/);
  });
  it('handles a null host gracefully', () => {
    const s: Stall = { kind: 'temporal', step_id: 3, host: null, delta_seconds: 300, window_seconds: 120 };
    expect(() => formatStall(s)).not.toThrow();
  });
});
