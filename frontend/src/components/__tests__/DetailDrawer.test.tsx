import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import DetailDrawer from '../DetailDrawer';

function renderDrawer(props: Partial<React.ComponentProps<typeof DetailDrawer>> = {}) {
  const onClose = vi.fn();
  const utils = render(
    <DetailDrawer open title="Host db-prod-01" onClose={onClose} {...props}>
      <button type="button">child-action</button>
      <p>child body content</p>
    </DetailDrawer>
  );
  return { onClose, ...utils };
}

describe('DetailDrawer', () => {
  it('renders nothing when closed', () => {
    render(<DetailDrawer open={false} title="X" onClose={vi.fn()}>hi</DetailDrawer>);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('portals into #modal-root with role=dialog, aria-modal, labelled title', () => {
    renderDrawer();
    const dlg = screen.getByRole('dialog');
    expect(dlg).toHaveAttribute('aria-modal', 'true');
    expect(document.getElementById('modal-root')?.contains(dlg)).toBe(true);
    expect(screen.getByText('Host db-prod-01')).toBeInTheDocument();
  });

  it('renders children', () => {
    renderDrawer();
    expect(screen.getByText('child body content')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'child-action' })).toBeInTheDocument();
  });

  it('renders an optional footer', () => {
    renderDrawer({ footer: <a href="/x">footer-link</a> });
    expect(screen.getByRole('link', { name: 'footer-link' })).toBeInTheDocument();
  });

  it('Esc closes', () => {
    const { onClose } = renderDrawer();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('close button closes', () => {
    const { onClose } = renderDrawer();
    fireEvent.click(screen.getByRole('button', { name: /close/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('backdrop click closes', () => {
    const { onClose } = renderDrawer();
    fireEvent.click(screen.getByTestId('drawer-backdrop'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('moves focus into the panel on open', () => {
    renderDrawer();
    expect(document.getElementById('modal-root')?.contains(document.activeElement)).toBe(true);
  });

  it('focus-trap: Tab keeps focus inside the panel (jsdom wrap invariant)', () => {
    // jsdom has no layout: offsetParent is always null for every element.
    // The component's focusable filter is:
    //   el.offsetParent !== null || el === document.activeElement
    // In jsdom this means only the currently active element qualifies, making the
    // focusable list a singleton at keydown time. True forward/backward wrap between
    // two distinct elements cannot be observed without real layout.
    //
    // What IS provable in jsdom: when the active element IS inside the panel and Tab
    // fires, the handler's `first === last` condition leaves focus on that same element
    // (it calls first.focus() === last.focus() === the current element), so focus never
    // escapes the panel. We assert that invariant here.
    const onClose = vi.fn();
    render(
      <DetailDrawer open title="Trap test" onClose={onClose}>
        <button type="button">child-one</button>
        <button type="button">child-two</button>
      </DetailDrawer>
    );

    const panelRoot = document.getElementById('modal-root')!;
    const childTwo = screen.getByRole('button', { name: 'child-two' });

    // Focus a panel element and fire forward Tab.
    childTwo.focus();
    expect(document.activeElement).toBe(childTwo);
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: false });
    // Focus must remain within the panel (not escape to document.body or outside).
    expect(panelRoot.contains(document.activeElement)).toBe(true);

    // Fire Shift+Tab from the same position.
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(panelRoot.contains(document.activeElement)).toBe(true);
  });

  it('restores focus to the opener on close', () => {
    const onClose = vi.fn();
    function Harness() {
      const [open, setOpen] = (require('react') as typeof import('react')).useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>opener</button>
          <DetailDrawer open={open} title="t" onClose={() => { setOpen(false); onClose(); }}>
            x
          </DetailDrawer>
        </>
      );
    }
    render(<Harness />);
    const opener = screen.getByRole('button', { name: 'opener' });
    opener.focus();
    fireEvent.click(opener);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(document.activeElement).toBe(opener);
  });
});
