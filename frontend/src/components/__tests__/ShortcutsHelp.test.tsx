import { describe, it, expect, vi } from 'vitest';
import { useRef, useState } from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ShortcutsHelp from '../ShortcutsHelp';

describe('ShortcutsHelp', () => {
  it('does not render anything when closed', () => {
    render(<ShortcutsHelp open={false} onClose={vi.fn()} />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('renders all binding rows when open', () => {
    render(<ShortcutsHelp open onClose={vi.fn()} />);
    const dialog = screen.getByRole('dialog');
    expect(dialog).toBeInTheDocument();
    // each binding has a <kbd> and a label
    for (const k of ['j', 'k', 'a', 'r', '/', '?']) {
      expect(screen.getByText(k, { selector: 'kbd' })).toBeInTheDocument();
    }
    expect(screen.getByText(/next alert/i)).toBeInTheDocument();
    expect(screen.getByText(/previous alert/i)).toBeInTheDocument();
    expect(screen.getByText(/acknowledge alert/i)).toBeInTheDocument();
  });

  it('Escape calls onClose', () => {
    const onClose = vi.fn();
    render(<ShortcutsHelp open onClose={onClose} />);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('the close button calls onClose', () => {
    const onClose = vi.fn();
    render(<ShortcutsHelp open onClose={onClose} />);
    fireEvent.click(screen.getByRole('button', { name: /close/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('backdrop click calls onClose', () => {
    const onClose = vi.fn();
    render(<ShortcutsHelp open onClose={onClose} />);
    fireEvent.click(screen.getByTestId('shortcuts-backdrop'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('returns focus to the trigger when closed', async () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      const triggerRef = useRef<HTMLButtonElement>(null);
      return (
        <>
          <button ref={triggerRef} onClick={() => setOpen(true)}>
            open shortcuts
          </button>
          <ShortcutsHelp open={open} onClose={() => setOpen(false)} returnFocusRef={triggerRef} />
        </>
      );
    }
    render(<Harness />);
    const trigger = screen.getByRole('button', { name: /open shortcuts/i });
    trigger.focus();
    fireEvent.click(trigger);
    await screen.findByRole('dialog');
    fireEvent.click(screen.getByRole('button', { name: /close/i }));
    await waitFor(() => expect(document.activeElement).toBe(trigger));
  });
});
