import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import Toaster from '../Toaster';
import { useToastStore } from '../../store/toast';

beforeEach(() => {
  vi.useFakeTimers();
  act(() => useToastStore.setState({ message: '', status: 'success', show: false }));
});
afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
});

describe('Toaster', () => {
  it('shows a toast with role=status aria-live=polite', () => {
    render(<Toaster />);
    act(() => useToastStore.getState().toast('Saved', 'success'));
    const status = screen.getByRole('status');
    expect(status).toHaveAttribute('aria-live', 'polite');
    expect(status).toHaveTextContent('Saved');
  });

  it('auto-dismisses after 4s', () => {
    render(<Toaster />);
    act(() => useToastStore.getState().toast('Bye'));
    expect(screen.getByRole('status')).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(4000));
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('manual ✕ dismisses immediately', () => {
    render(<Toaster />);
    act(() => useToastStore.getState().toast('Manual'));
    fireEvent.click(screen.getByLabelText('Close dialog'));
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('newest replaces the previous', () => {
    render(<Toaster />);
    act(() => useToastStore.getState().toast('First'));
    act(() => useToastStore.getState().toast('Second', 'error'));
    const statuses = screen.getAllByRole('status');
    expect(statuses).toHaveLength(1);
    expect(statuses[0]).toHaveTextContent('Second');
  });
});
