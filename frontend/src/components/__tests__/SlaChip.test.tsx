import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import SlaChip from '../SlaChip';

const NOW = new Date('2026-05-31T12:00:00.000Z');

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

function isoAgo(ms: number): string {
  return new Date(NOW.getTime() - ms).toISOString();
}

const H = 60 * 60 * 1000;
const D = 24 * H;

describe('SlaChip', () => {
  it('humanizes a few-hours age as "Nh"', () => {
    render(<SlaChip createdAt={isoAgo(3 * H)} status="open" />);
    expect(screen.getByText('3h')).toBeInTheDocument();
  });

  it('humanizes a multi-day age as "Nd"', () => {
    render(<SlaChip createdAt={isoAgo(2 * D)} status="open" />);
    expect(screen.getByText('2d')).toBeInTheDocument();
  });

  it('shows minutes for very fresh alerts', () => {
    render(<SlaChip createdAt={isoAgo(5 * 60 * 1000)} status="open" />);
    expect(screen.getByText('5m')).toBeInTheDocument();
  });

  it('freezes the delta at resolvedAt for terminal status', () => {
    // created 10d ago, resolved 8d ago → frozen age = 2d (not 10d)
    render(
      <SlaChip
        createdAt={isoAgo(10 * D)}
        resolvedAt={isoAgo(8 * D)}
        status="resolved"
      />
    );
    expect(screen.getByText('2d')).toBeInTheDocument();
  });

  it('green band under 4h', () => {
    const { container } = render(<SlaChip createdAt={isoAgo(1 * H)} status="open" />);
    const chip = container.querySelector('[data-band]') as HTMLElement;
    expect(chip.getAttribute('data-band')).toBe('green');
  });

  it('amber band under 24h', () => {
    const { container } = render(<SlaChip createdAt={isoAgo(10 * H)} status="open" />);
    const chip = container.querySelector('[data-band]') as HTMLElement;
    expect(chip.getAttribute('data-band')).toBe('amber');
  });

  it('red band at or above 24h', () => {
    const { container } = render(<SlaChip createdAt={isoAgo(30 * H)} status="open" />);
    const chip = container.querySelector('[data-band]') as HTMLElement;
    expect(chip.getAttribute('data-band')).toBe('red');
  });

  it('carries a full duration in the aria-label', () => {
    render(<SlaChip createdAt={isoAgo(3 * H)} status="open" />);
    // open → "Open for ..." aria-label including the duration
    const el = screen.getByLabelText(/Open for/i);
    expect(el).toBeInTheDocument();
    expect(el.getAttribute('aria-label')).toMatch(/3h/);
  });

  it('uses the resolved aria-label for terminal status', () => {
    render(
      <SlaChip createdAt={isoAgo(10 * D)} resolvedAt={isoAgo(8 * D)} status="closed" />
    );
    expect(screen.getByLabelText(/Resolved in/i)).toBeInTheDocument();
  });
});
