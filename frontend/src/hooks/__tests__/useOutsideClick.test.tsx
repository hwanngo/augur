import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import useOutsideClick from '../useOutsideClick';

function Harness() {
  const [open, setOpen, ref] = useOutsideClick();
  return (
    <div>
      <button onClick={() => setOpen(true)}>open</button>
      <div ref={ref} data-testid="box">
        {open ? <span>inside</span> : null}
      </div>
      <button>outside</button>
    </div>
  );
}

describe('useOutsideClick', () => {
  it('opens, stays open on inside click, closes on outside mousedown', () => {
    render(<Harness />);
    fireEvent.click(screen.getByText('open'));
    expect(screen.getByText('inside')).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByTestId('box'));
    expect(screen.getByText('inside')).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByText('outside'));
    expect(screen.queryByText('inside')).not.toBeInTheDocument();
  });
});
