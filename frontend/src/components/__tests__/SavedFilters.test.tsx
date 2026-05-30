import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import SavedFilters from '../SavedFilters';
import { ConfirmHost } from '../useConfirm';

interface DemoFilter { severity: string; zone: string }

beforeEach(() => localStorage.clear());
afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

function renderWith(props: Partial<React.ComponentProps<typeof SavedFilters<DemoFilter>>> = {}) {
  const onApply = vi.fn();
  const show = vi.fn();
  render(
    <>
      <SavedFilters<DemoFilter>
        scope="dashboard"
        user="alice"
        current={{ severity: 'CRITICAL', zone: 'corp' }}
        onApply={onApply}
        show={show}
        {...props}
      />
      <ConfirmHost />
    </>
  );
  return { onApply, show };
}

describe('SavedFilters', () => {
  it('renders a recall combobox with the scoped accessible name', () => {
    renderWith();
    expect(screen.getByRole('combobox', { name: /saved filters/i })).toBeInTheDocument();
  });

  it('saves the current filter under a typed name and persists it', async () => {
    const { show } = renderWith();
    fireEvent.click(screen.getByRole('button', { name: /save filter/i }));
    const input = screen.getByRole('textbox', { name: /filter name/i });
    fireEvent.change(input, { target: { value: 'my-view' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    // Open the dropdown to see options
    fireEvent.click(screen.getByRole('combobox', { name: /saved filters/i }));
    await waitFor(() => {
      expect(screen.getByRole('option', { name: 'my-view' })).toBeInTheDocument();
    });
    expect(show).toHaveBeenCalledWith('Saved filter "my-view"', 'success');
  });

  it('does not save when the name is empty', () => {
    const { show } = renderWith();
    fireEvent.click(screen.getByRole('button', { name: /save filter/i }));
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(show).not.toHaveBeenCalled();
    // Open dropdown — no saved filters means zero options
    fireEvent.click(screen.getByRole('combobox', { name: /saved filters/i }));
    expect(screen.queryAllByRole('option')).toHaveLength(0);
  });

  it('recalling a saved filter fires onApply with the stored value', async () => {
    const { onApply } = renderWith();
    fireEvent.click(screen.getByRole('button', { name: /save filter/i }));
    fireEvent.change(screen.getByRole('textbox', { name: /filter name/i }), { target: { value: 'view-a' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    // Open dropdown and click the saved filter option
    fireEvent.click(screen.getByRole('combobox', { name: /saved filters/i }));
    await waitFor(() => expect(screen.getByRole('option', { name: 'view-a' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('option', { name: 'view-a' }));
    expect(onApply).toHaveBeenCalledWith({ severity: 'CRITICAL', zone: 'corp' });
  });

  it('deletes the selected saved filter', async () => {
    const { show } = renderWith();
    fireEvent.click(screen.getByRole('button', { name: /save filter/i }));
    fireEvent.change(screen.getByRole('textbox', { name: /filter name/i }), { target: { value: 'gone' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    // Open dropdown and select 'gone'
    fireEvent.click(screen.getByRole('combobox', { name: /saved filters/i }));
    await waitFor(() => expect(screen.getByRole('option', { name: 'gone' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('option', { name: 'gone' }));

    fireEvent.click(screen.getByRole('button', { name: /delete saved filter "gone"/i }));
    // now a confirm dialog appears — confirm it
    const dialog = await screen.findByRole('dialog');
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: /delete/i }));
    });
    // After deletion, combobox should show placeholder again
    await waitFor(() => {
      expect(screen.getByRole('combobox', { name: /saved filters/i })).toHaveTextContent(/saved filters…/i);
    });
    expect(show).toHaveBeenCalledWith('Filter deleted', 'success');
  });
});
