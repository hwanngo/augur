import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { useConfirm, ConfirmHost } from '../useConfirm';
import { useConfirmStore } from '../../store/confirm';

function Trigger({ onResult }: { onResult: (r: boolean) => void }) {
  const confirm = useConfirm();
  return (
    <button onClick={async () => onResult(await confirm({ title: 'Delete?', message: 'Sure?' }))}>
      go
    </button>
  );
}

function setup() {
  const results: boolean[] = [];
  render(
    <>
      <Trigger onResult={(r) => results.push(r)} />
      <ConfirmHost />
    </>
  );
  return results;
}

describe('useConfirm', () => {
  it('resolves true when confirmed', async () => {
    const results = setup();
    fireEvent.click(screen.getByText('go'));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /confirm/i }));
    });
    expect(results).toEqual([true]);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('resolves false on cancel and Esc', async () => {
    const results = setup();
    fireEvent.click(screen.getByText('go'));
    await act(async () => fireEvent.click(screen.getByText('Cancel')));
    fireEvent.click(screen.getByText('go'));
    await act(async () => fireEvent.keyDown(document, { key: 'Escape' }));
    expect(results).toEqual([false, false]);
  });

  it('only ever mounts one dialog', () => {
    setup();
    fireEvent.click(screen.getByText('go'));
    expect(screen.getAllByRole('dialog')).toHaveLength(1);
    // reset the store so other tests start clean
    act(() => useConfirmStore.getState().dismiss(false));
  });

  it('calling confirm() while a prior confirm is still open resolves the first promise to false (leak-guard)', async () => {
    // Wire up two independent result collectors that each call confirm()
    const firstResults: boolean[] = [];
    const secondResults: boolean[] = [];

    function TwoTrigger() {
      const confirm = useConfirm();
      return (
        <>
          <button
            data-testid="first"
            onClick={async () => firstResults.push(await confirm({ title: 'First?', message: 'A' }))}
          >
            first
          </button>
          <button
            data-testid="second"
            onClick={async () => secondResults.push(await confirm({ title: 'Second?', message: 'B' }))}
          >
            second
          </button>
        </>
      );
    }

    render(
      <>
        <TwoTrigger />
        <ConfirmHost />
      </>
    );

    // Open the first confirm — do NOT close it yet
    fireEvent.click(screen.getByTestId('first'));
    expect(screen.getByText('First?')).toBeInTheDocument();

    // Open the second confirm while the first is still pending — the store's
    // leak-guard must resolve the first promise to false immediately.
    await act(async () => {
      fireEvent.click(screen.getByTestId('second'));
    });

    // First promise should have been resolved to false by the leak-guard
    expect(firstResults).toEqual([false]);
    // Second dialog is now showing
    expect(screen.getByText('Second?')).toBeInTheDocument();

    // Confirm the second one normally
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /confirm/i }));
    });
    expect(secondResults).toEqual([true]);
  });
});
