import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import useOutsideClick from '../hooks/useOutsideClick';

export interface DropdownOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface DropdownProps {
  value: string;
  onChange: (value: string) => void;
  options: DropdownOption[];
  label?: string;
  'aria-label'?: string;
  placeholder?: string;
  hint?: string;
  error?: string;
  disabled?: boolean;
  id?: string;
  className?: string;
  /** @deprecated The listbox is always portaled now; this prop is accepted for back-compat. */
  menuPortal?: boolean;
}

export default function Dropdown({
  value,
  onChange,
  options,
  label,
  'aria-label': ariaLabel,
  placeholder,
  hint,
  error,
  disabled,
  id,
  className,
}: DropdownProps) {
  const { t } = useTranslation();
  const menuRef = useRef<HTMLDivElement>(null);
  // The listbox is portaled to <body>, so it lives outside the container in the DOM.
  // Pass menuRef as the "extra inside" element so a mousedown on an option doesn't
  // register as an outside click and close the menu before the click selects.
  const [open, setOpen, containerRef] = useOutsideClick(menuRef);
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const autoId = useId();
  const triggerId = id ?? autoId;
  const listboxId = `${triggerId}-listbox`;

  // Position the portaled listbox at the trigger (fixed = viewport coords; no scroll offset).
  const [menuStyle, setMenuStyle] = useState<React.CSSProperties>({});

  const selectedIndex = options.findIndex((o) => o.value === value);
  const selected = selectedIndex >= 0 ? options[selectedIndex] : null;
  const resolvedPlaceholder = placeholder ?? t('common.select');

  const positionMenu = useCallback(() => {
    if (!triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    setMenuStyle({
      position: 'fixed',
      top: rect.bottom + 4,
      left: rect.left,
      minWidth: rect.width,
      zIndex: 9999,
    });
  }, []);

  useEffect(() => {
    if (!open) return;
    setHighlightedIndex(selectedIndex >= 0 ? selectedIndex : 0);
    positionMenu();
    // Keep the fixed menu attached to the trigger as the page/containers scroll or resize.
    const reposition = () => positionMenu();
    window.addEventListener('scroll', reposition, true); // capture: catch scrolling ancestors
    window.addEventListener('resize', reposition);
    return () => {
      window.removeEventListener('scroll', reposition, true);
      window.removeEventListener('resize', reposition);
    };
  }, [open, selectedIndex, positionMenu]);

  const selectAt = (i: number) => {
    const opt = options[i];
    if (!opt || opt.disabled) return;
    onChange(opt.value);
    setOpen(false);
    triggerRef.current?.focus();
  };

  const moveHighlight = (dir: 1 | -1) => {
    setHighlightedIndex((i) => {
      let next = i;
      for (let step = 0; step < options.length; step++) {
        next = Math.min(Math.max(next + dir, 0), options.length - 1);
        if (!options[next]?.disabled) return next;
        if (next === 0 || next === options.length - 1) break;
      }
      return i;
    });
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (disabled) return;
    switch (e.key) {
      case 'Enter':
      case ' ':
        e.preventDefault();
        if (open) selectAt(highlightedIndex);
        else setOpen(true);
        break;
      case 'ArrowDown':
        e.preventDefault();
        if (!open) setOpen(true);
        else moveHighlight(1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        if (!open) setOpen(true);
        else moveHighlight(-1);
        break;
      case 'Escape':
        e.preventDefault();
        e.stopPropagation(); // Fix 3: prevent Esc from bubbling to AlertDrawer
        setOpen(false);
        break;
      case 'Tab':
        setOpen(false);
        break;
    }
  };

  const listbox = open ? (
    <div
      ref={menuRef}
      id={listboxId}
      role="listbox"
      aria-label={ariaLabel ?? label}
      className="rounded-lg border overflow-auto max-h-60 shadow-xl"
      style={{ ...menuStyle, background: 'var(--panel)', borderColor: 'var(--border)' }}
    >
      {options.length === 0 ? (
        <div className="px-3 py-1.5 text-xs" style={{ color: 'var(--muted)' }}>
          {t('common.noOptions')}
        </div>
      ) : (
        options.map((opt, i) => {
          const isSelected = opt.value === value;
          const isHighlighted = i === highlightedIndex;
          return (
            // Listbox pattern: keyboard is driven from the combobox trigger (handleKeyDown +
            // highlightedIndex); options are intentionally not individually focusable. Mouse click
            // is a redundant convenience over the already-accessible keyboard path.
            // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/interactive-supports-focus
            <div
              key={opt.value}
              id={`${triggerId}-opt-${i}`}
              role="option"
              aria-selected={isSelected}
              aria-disabled={opt.disabled || undefined}
              title={opt.label}
              onClick={() => selectAt(i)}
              onMouseEnter={() => !opt.disabled && setHighlightedIndex(i)}
              className="px-3 py-1.5 text-xs transition-colors truncate"
              style={{
                background: isHighlighted && !opt.disabled ? '#21262d' : 'transparent',
                color: opt.disabled ? 'var(--muted)' : isSelected ? 'var(--accent)' : 'var(--fg)',
                opacity: opt.disabled ? 0.5 : 1,
                cursor: opt.disabled ? 'not-allowed' : 'pointer',
              }}
            >
              {opt.label}
            </div>
          );
        })
      )}
    </div>
  ) : null;

  return (
    <div ref={containerRef} className={`flex flex-col gap-1 ${className ?? ''}`}>
      {label && (
        <label htmlFor={triggerId} className="text-xs font-medium" style={{ color: 'var(--muted)' }}>
          {label}
        </label>
      )}
      <div className="relative">
        <button
          ref={triggerRef}
          id={triggerId}
          type="button"
          role="combobox"
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-controls={listboxId}
          aria-label={ariaLabel}
          aria-activedescendant={open && options.length > 0 ? `${triggerId}-opt-${highlightedIndex}` : undefined}
          disabled={disabled}
          onClick={() => !disabled && setOpen(!open)}
          onKeyDown={handleKeyDown}
          className="w-full px-3 py-1.5 text-xs rounded-lg border text-left flex items-center justify-between gap-2 transition-colors cursor-pointer select-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)] disabled:opacity-50 disabled:cursor-not-allowed"
          style={{
            background: 'var(--bg)',
            borderColor: error ? '#a02020' : open ? 'var(--focus)' : 'var(--border)',
            color: selected ? 'var(--fg)' : 'var(--muted)',
          }}
        >
          <span>{selected?.label ?? resolvedPlaceholder}</span>
          <ChevronDown
            size={14}
            aria-hidden
            className={`flex-shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
            style={{ color: 'var(--muted)' }}
          />
        </button>

      </div>

      {listbox && createPortal(listbox, document.body)}

      {hint && !error && <p className="text-xs" style={{ color: 'var(--muted)' }}>{hint}</p>}
      {error && <p className="text-xs" style={{ color: '#ffb4ab' }}>{error}</p>}
    </div>
  );
}
