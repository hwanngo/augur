import { useEffect, useRef, useId } from 'react';
import { createPortal } from 'react-dom';
import { X, Loader2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

export interface DialogProps {
  open: boolean;
  title: string;
  onClose: () => void;
  onConfirm?: () => void | Promise<void>;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'default' | 'destructive';
  loading?: boolean;
  message?: string;
  children?: React.ReactNode;
  wide?: boolean;
  closeOnBackdrop?: boolean;
}

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

export default function Dialog({
  open,
  title,
  onClose,
  onConfirm,
  confirmLabel,
  cancelLabel,
  variant = 'default',
  loading = false,
  message,
  children,
  wide = false,
  closeOnBackdrop,
}: DialogProps) {
  // Destructive dialogs must not be dismissed by an accidental backdrop click;
  // an explicit prop always wins, but the default differs by variant.
  const effectiveCloseOnBackdrop = closeOnBackdrop ?? (variant !== 'destructive');
  const { t } = useTranslation();
  const panelRef = useRef<HTMLDivElement>(null);
  const openerRef = useRef<HTMLElement | null>(null);
  const titleId = useId();

  // Capture opener + restore focus on close.
  useEffect(() => {
    if (!open) return;
    openerRef.current = (document.activeElement as HTMLElement) ?? null;
    // focus first focusable in the panel
    const node = panelRef.current?.querySelector<HTMLElement>(FOCUSABLE);
    node?.focus();
    return () => {
      openerRef.current?.focus?.();
    };
  }, [open]);

  // Keyboard: Esc → close; Enter → confirm (unless in a textarea or no onConfirm); Tab → trap.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      } else if (
        e.key === 'Enter' &&
        onConfirm &&
        (e.target as HTMLElement).tagName !== 'TEXTAREA'
      ) {
        void onConfirm();
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
  }, [open, onConfirm, onClose]);

  if (!open) return null;
  const modalRoot = document.getElementById('modal-root') ?? document.body;
  const confirmClass = variant === 'destructive' ? 'btn-danger' : 'btn-primary';

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
      <div
        data-testid="dialog-backdrop"
        className="absolute inset-0 bg-black/60"
        onClick={() => effectiveCloseOnBackdrop && onClose()}
        aria-hidden
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className={`relative z-10 w-full ${wide ? 'max-w-3xl' : 'max-w-md'} rounded-xl border shadow-xl flex flex-col max-h-[90vh]`}
        style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
      >
        <div className="flex items-center justify-between p-4 border-b shrink-0" style={{ borderColor: 'var(--border)' }}>
          <h2 id={titleId} className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
            {title}
          </h2>
          <button type="button" onClick={onClose} className="btn-ghost p-1" aria-label={t('common.closeDialog')}>
            <X size={14} aria-hidden />
          </button>
        </div>

        <div className="p-4 overflow-y-auto min-h-0">
          {message && <p className="text-sm" style={{ color: 'var(--muted)' }}>{message}</p>}
          {children}
        </div>

        <div className="flex gap-3 justify-end p-4 border-t shrink-0" style={{ borderColor: 'var(--border)' }}>
          <button type="button" className="btn-secondary" onClick={onClose} disabled={loading}>
            {cancelLabel ?? t('common.cancel')}
          </button>
          {onConfirm && (
            <button type="button" className={confirmClass} onClick={() => void onConfirm()} disabled={loading}>
              {loading ? <Loader2 size={14} className="animate-spin" aria-hidden /> : null}
              {confirmLabel ?? t('common.confirm')}
            </button>
          )}
        </div>
      </div>
    </div>,
    modalRoot
  );
}
