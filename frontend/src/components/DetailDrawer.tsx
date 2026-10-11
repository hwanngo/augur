import { useEffect, useRef, useId, useLayoutEffect } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

export interface DetailDrawerProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  wide?: boolean;
}

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

export default function DetailDrawer({
  open,
  title,
  onClose,
  children,
  footer,
  wide = false,
}: DetailDrawerProps) {
  const { t } = useTranslation();
  const panelRef = useRef<HTMLDivElement>(null);
  const openerRef = useRef<HTMLElement | null>(null);
  const titleId = useId();

  // Capture opener + move focus into panel; restore on close.
  useEffect(() => {
    if (!open) return;
    openerRef.current = (document.activeElement as HTMLElement) ?? null;
    const node = panelRef.current?.querySelector<HTMLElement>(FOCUSABLE);
    node?.focus();
    return () => {
      openerRef.current?.focus?.();
    };
  }, [open]);

  // Esc → close; Tab → trapped within the panel. Layout effect so the listener is live as soon
  // as the drawer is committed (a passive effect leaves a window where Esc is dropped).
  useLayoutEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      } else if (e.key === 'Tab' && panelRef.current) {
        const focusables = Array.from(
          panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)
        ).filter((el) => el.offsetParent !== null || el === document.activeElement);
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);

  if (!open) return null;
  const modalRoot = document.getElementById('modal-root') ?? document.body;

  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        data-testid="drawer-backdrop"
        className="absolute inset-0 bg-black/60"
        onClick={onClose}
        aria-hidden
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className={`relative z-10 h-full w-full ${wide ? 'max-w-lg' : 'max-w-md'} flex flex-col border-l shadow-xl animate-[drawerIn_180ms_ease-out]`}
        style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
      >
        <div
          className="flex items-center justify-between p-4 border-b shrink-0 sticky top-0 z-10"
          style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
        >
          <h2 id={titleId} className="text-sm font-semibold truncate pr-2" style={{ color: 'var(--fg)' }}>
            {title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="btn-ghost py-1.5 px-1.5 text-xs shrink-0"
            aria-label={t('common.closeDialog')}
          >
            <X size={14} aria-hidden />
          </button>
        </div>

        <div className="p-4 overflow-y-auto min-h-0 flex-1">{children}</div>

        {footer && (
          <div
            className="flex flex-wrap gap-2 p-4 border-t shrink-0"
            style={{ borderColor: 'var(--border)' }}
          >
            {footer}
          </div>
        )}
      </div>
    </div>,
    modalRoot
  );
}
