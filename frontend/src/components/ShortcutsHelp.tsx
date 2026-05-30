import { useEffect, type RefObject } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

interface Props {
  open: boolean;
  onClose: () => void;
  /** Focus is returned here when the overlay closes (the trigger button). */
  returnFocusRef?: RefObject<HTMLElement | null>;
}

const BINDINGS: { key: string; labelKey: string }[] = [
  { key: 'j', labelKey: 'shortcuts.navDown' },
  { key: 'k', labelKey: 'shortcuts.navUp' },
  { key: 'a', labelKey: 'shortcuts.ack' },
  { key: 'r', labelKey: 'shortcuts.resolve' },
  { key: '/', labelKey: 'shortcuts.focusFilters' },
  { key: '?', labelKey: 'shortcuts.help' },
];

/**
 * Keyboard-shortcuts help overlay. Portal dialog (mirrors AlertDrawer) listing
 * every Alerts-list binding. Escape, the close button and a backdrop click all
 * call `onClose`; on close, focus returns to the trigger (`returnFocusRef`).
 */
export default function ShortcutsHelp({ open, onClose, returnFocusRef }: Props) {
  const { t } = useTranslation();

  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [open, onClose]);

  // Return focus to the trigger when the overlay closes.
  useEffect(() => {
    if (open) return;
    returnFocusRef?.current?.focus();
  }, [open, returnFocusRef]);

  if (!open) return null;

  const root = document.getElementById('modal-root') ?? document.body;
  const content = (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
      <div
        data-testid="shortcuts-backdrop"
        className="absolute inset-0 bg-black/60"
        onClick={onClose}
        aria-hidden
      />
      <div
        className="relative z-10 w-full max-w-md rounded-xl border shadow-xl"
        style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
        role="dialog"
        aria-modal
        aria-labelledby="shortcuts-title"
      >
        <div
          className="flex items-center justify-between p-4 border-b"
          style={{ borderColor: 'var(--border)' }}
        >
          <h2 id="shortcuts-title" className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
            {t('shortcuts.title')}
          </h2>
          <button
            type="button"
            onClick={onClose}
            // Focus-on-open: dialog pattern moves initial focus into the modal (the close button) on mount.
            // eslint-disable-next-line jsx-a11y/no-autofocus
            autoFocus
            className="btn-ghost p-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
            aria-label={t('common.closeDialog')}
          >
            <X size={14} aria-hidden />
          </button>
        </div>
        <dl className="p-4 space-y-2">
          {BINDINGS.map((b) => (
            <div key={b.key} className="flex items-center justify-between gap-4">
              <dd className="text-xs" style={{ color: 'var(--fg)' }}>
                {t(b.labelKey)}
              </dd>
              <dt>
                <kbd
                  className="px-2 py-0.5 rounded border text-xs font-mono"
                  style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
                >
                  {b.key}
                </kbd>
              </dt>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
  return createPortal(content, root);
}
