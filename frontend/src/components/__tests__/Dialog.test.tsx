import { describe, it, expect, vi } from 'vitest';
import { useState } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import Dialog from '../Dialog';

function FocusHarness() {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button onClick={() => setOpen(true)}>opener</button>
      <Dialog open={open} title="X" message="m" onClose={() => setOpen(false)} onConfirm={() => {}} />
    </div>
  );
}

describe('Dialog', () => {
  it('renders to #modal-root with role=dialog aria-modal when open', () => {
    render(<Dialog open title="Revoke session" message="Are you sure?" onClose={() => {}} onConfirm={() => {}} />);
    const dlg = screen.getByRole('dialog');
    expect(dlg).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByText('Revoke session')).toBeInTheDocument();
    // portalled into #modal-root, not the test container root
    expect(document.getElementById('modal-root')?.contains(dlg)).toBe(true);
  });

  it('renders nothing when open=false', () => {
    render(<Dialog open={false} title="X" onClose={() => {}} />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('Esc, backdrop click, ✕, and Cancel all call onClose', () => {
    const onClose = vi.fn();
    render(<Dialog open title="X" message="m" onClose={onClose} onConfirm={() => {}} />);
    fireEvent.keyDown(document, { key: 'Escape' });
    fireEvent.click(screen.getByLabelText('Close dialog'));
    fireEvent.click(screen.getByText('Cancel'));
    fireEvent.click(screen.getByTestId('dialog-backdrop'));
    expect(onClose).toHaveBeenCalledTimes(4);
  });

  it('Enter calls onConfirm, but not when focus is in a textarea', () => {
    const onConfirm = vi.fn();
    render(
      <Dialog open title="X" onClose={() => {}} onConfirm={onConfirm}>
        <textarea aria-label="note" />
      </Dialog>
    );
    fireEvent.keyDown(document, { key: 'Enter' });
    expect(onConfirm).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(screen.getByLabelText('note'), { key: 'Enter' });
    expect(onConfirm).toHaveBeenCalledTimes(1); // unchanged
  });

  it('destructive variant renders confirm with .btn-danger', () => {
    render(<Dialog open title="X" message="m" variant="destructive" confirmLabel="Delete" onClose={() => {}} onConfirm={() => {}} />);
    expect(screen.getByText('Delete')).toHaveClass('btn-danger');
  });

  it('backdrop click does NOT call onClose for destructive variant (no accidental dismiss)', () => {
    const onClose = vi.fn();
    render(
      <Dialog open title="Confirm delete" message="This is permanent." variant="destructive" onClose={onClose} onConfirm={() => {}} />
    );
    fireEvent.click(screen.getByTestId('dialog-backdrop'));
    expect(onClose).not.toHaveBeenCalled();
  });

  it('backdrop click DOES call onClose for default variant', () => {
    const onClose = vi.fn();
    render(<Dialog open title="X" message="m" onClose={onClose} onConfirm={() => {}} />);
    fireEvent.click(screen.getByTestId('dialog-backdrop'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('explicit closeOnBackdrop=true overrides destructive default and allows backdrop dismiss', () => {
    const onClose = vi.fn();
    render(
      <Dialog open title="X" message="m" variant="destructive" closeOnBackdrop={true} onClose={onClose} onConfirm={() => {}} />
    );
    fireEvent.click(screen.getByTestId('dialog-backdrop'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('omitting onConfirm renders an informational modal (no confirm button)', () => {
    render(<Dialog open title="Help" message="info" onClose={() => {}} />);
    expect(screen.queryByText('Confirm')).not.toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument(); // close-only footer keeps Cancel
  });

  it('loading disables footer buttons', () => {
    render(<Dialog open title="X" message="m" loading onClose={() => {}} onConfirm={() => {}} />);
    expect(screen.getByText('Cancel')).toBeDisabled();
    expect(screen.getByRole('button', { name: /confirm/i })).toBeDisabled();
  });

  it('traps focus and returns focus to the opener on close', () => {
    render(<FocusHarness />);
    const opener = screen.getByText('opener');
    opener.focus();
    fireEvent.click(opener);
    // first focusable inside the dialog is focused on open
    expect(document.activeElement).not.toBe(opener);
    expect(document.getElementById('modal-root')?.contains(document.activeElement)).toBe(true);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(document.activeElement).toBe(opener); // return focus
  });

  it('Tab from the last focusable wraps to the first (focus cycle forward)', () => {
    render(<FocusHarness />);
    fireEvent.click(screen.getByText('opener'));
    // Gather all focusable buttons inside the dialog panel.
    // jsdom sets offsetParent=null for every element (no layout engine), which would cause
    // the trap's visibility filter to skip them all.  We mock offsetParent to a non-null
    // sentinel so the trap treats them as "visible" — matching real-browser behaviour.
    const panel = screen.getByRole('dialog');
    const FOCUSABLE =
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const focusables = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE));
    expect(focusables.length).toBeGreaterThanOrEqual(2);
    // Patch offsetParent so the trap's filter considers every element visible.
    focusables.forEach((el) => {
      Object.defineProperty(el, 'offsetParent', { configurable: true, get: () => panel });
    });
    const last = focusables[focusables.length - 1];
    last.focus();
    expect(document.activeElement).toBe(last);
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: false });
    expect(document.activeElement).toBe(focusables[0]);
  });

  it('Shift+Tab from the first focusable wraps to the last (focus cycle backward)', () => {
    render(<FocusHarness />);
    fireEvent.click(screen.getByText('opener'));
    const panel = screen.getByRole('dialog');
    const FOCUSABLE =
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const focusables = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE));
    expect(focusables.length).toBeGreaterThanOrEqual(2);
    // Patch offsetParent so the trap's filter considers every element visible.
    focusables.forEach((el) => {
      Object.defineProperty(el, 'offsetParent', { configurable: true, get: () => panel });
    });
    const first = focusables[0];
    first.focus();
    expect(document.activeElement).toBe(first);
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(focusables[focusables.length - 1]);
  });
});
