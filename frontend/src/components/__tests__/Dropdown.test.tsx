import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import Dropdown from '../Dropdown';

const OPTIONS = [
  { value: 'a', label: 'Apple' },
  { value: 'b', label: 'Banana' },
  { value: 'c', label: 'Cherry', disabled: true },
];

function setup(value = '', extra = {}) {
  const onChange = vi.fn();
  render(<Dropdown value={value} onChange={onChange} options={OPTIONS} aria-label="Fruit" {...extra} />);
  return { onChange };
}

describe('Dropdown', () => {
  it('renders a combobox showing placeholder when no value', () => {
    setup('', { placeholder: 'Pick one' });
    const trigger = screen.getByRole('combobox', { name: 'Fruit' });
    expect(trigger).toHaveTextContent('Pick one');
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
  });

  it('opens to a listbox of options and selects on click', () => {
    const { onChange } = setup();
    fireEvent.click(screen.getByRole('combobox', { name: 'Fruit' }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('option', { name: 'Banana' }));
    expect(onChange).toHaveBeenCalledWith('b');
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument(); // closed
  });

  it('mousedown on a (portaled) option does not close the menu before the click selects', () => {
    // Real-browser regression: the menu is portaled to <body>, outside the container.
    // A mousedown on an option must be treated as "inside" so the outside-click handler
    // does not close it before the click fires (RTL's fireEvent.click skips mousedown,
    // which is why this needs an explicit test).
    const { onChange } = setup();
    fireEvent.click(screen.getByRole('combobox', { name: 'Fruit' }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    fireEvent.mouseDown(document.body); // genuine outside → closes
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    // re-open; mousedown ON the option must keep it open, then click selects
    fireEvent.click(screen.getByRole('combobox', { name: 'Fruit' }));
    fireEvent.mouseDown(screen.getByRole('option', { name: 'Banana' }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('option', { name: 'Banana' }));
    expect(onChange).toHaveBeenCalledWith('b');
  });

  it('shows a no-options state when options is empty (no empty box)', () => {
    render(<Dropdown value="" onChange={() => {}} options={[]} aria-label="Empty" />);
    fireEvent.click(screen.getByRole('combobox', { name: 'Empty' }));
    expect(screen.getByRole('listbox')).toHaveTextContent(/no options/i);
    expect(screen.queryAllByRole('option')).toHaveLength(0);
  });

  it('keyboard: ArrowDown highlights, Enter selects, focus returns to trigger', () => {
    const { onChange } = setup();
    const trigger = screen.getByRole('combobox', { name: 'Fruit' });
    trigger.focus();
    fireEvent.keyDown(trigger, { key: 'ArrowDown' }); // open + highlight 0
    fireEvent.keyDown(trigger, { key: 'ArrowDown' }); // highlight 1
    fireEvent.keyDown(trigger, { key: 'Enter' });
    expect(onChange).toHaveBeenCalledWith('b');
    expect(document.activeElement).toBe(trigger);
  });

  it('Escape and Tab close the listbox', () => {
    setup();
    const trigger = screen.getByRole('combobox', { name: 'Fruit' });
    fireEvent.click(trigger);
    fireEvent.keyDown(trigger, { key: 'Escape' });
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    fireEvent.click(trigger);
    fireEvent.keyDown(trigger, { key: 'Tab' });
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('Esc closes the listbox and stops propagation (Fix 3: scoping)', () => {
    const parentHandler = vi.fn();
    render(
      <div onKeyDown={parentHandler}>
        <Dropdown value="" onChange={() => {}} options={OPTIONS} aria-label="Fruit" />
      </div>
    );
    const trigger = screen.getByRole('combobox', { name: 'Fruit' });
    fireEvent.click(trigger);
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    fireEvent.keyDown(trigger, { key: 'Escape' });
    // listbox closed
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    // Esc did not propagate to the parent
    expect(parentHandler).not.toHaveBeenCalled();
  });

  it('click-outside closes the listbox', () => {
    render(
      <div>
        <Dropdown value="" onChange={() => {}} options={OPTIONS} aria-label="Fruit" />
        <button>outside</button>
      </div>
    );
    fireEvent.click(screen.getByRole('combobox', { name: 'Fruit' }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByText('outside'));
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('does not select a disabled option', () => {
    const { onChange } = setup();
    fireEvent.click(screen.getByRole('combobox', { name: 'Fruit' }));
    fireEvent.click(screen.getByRole('option', { name: 'Cherry' }));
    expect(onChange).not.toHaveBeenCalled();
  });

  it('disabled trigger does not open', () => {
    setup('', { disabled: true });
    const trigger = screen.getByRole('combobox', { name: 'Fruit' });
    fireEvent.click(trigger);
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('shows the selected option label and renders error/hint', () => {
    render(<Dropdown value="a" onChange={() => {}} options={OPTIONS} aria-label="Fruit" error="Bad" />);
    expect(screen.getByRole('combobox', { name: 'Fruit' })).toHaveTextContent('Apple');
    expect(screen.getByText('Bad')).toBeInTheDocument();
  });

  it('menuPortal: renders listbox via portal but still opens and selects (Fix 2)', () => {
    const onChange = vi.fn();
    render(
      <Dropdown
        value=""
        onChange={onChange}
        options={OPTIONS}
        aria-label="Fruit"
        menuPortal
      />
    );
    const trigger = screen.getByRole('combobox', { name: 'Fruit' });
    fireEvent.click(trigger);
    // listbox is portaled into document.body but still accessible via role
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('option', { name: 'Banana' }));
    expect(onChange).toHaveBeenCalledWith('b');
    // closed after selection
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });
});
