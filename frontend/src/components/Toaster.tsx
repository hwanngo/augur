import { useEffect, useRef } from 'react';
import { Check, AlertTriangle, AlertCircle, Info, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useToastStore, type ToastStatus } from '../store/toast';

const ICON = {
  success: Check,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
} as const;

const ACCENT: Record<ToastStatus, string> = {
  success: 'var(--accent)',
  error: '#ffb4ab',
  warning: 'var(--muted)',
  info: 'var(--muted)',
};

export default function Toaster() {
  const { t } = useTranslation();
  const message = useToastStore((s) => s.message);
  const status = useToastStore((s) => s.status);
  const show = useToastStore((s) => s.show);
  const dismiss = useToastStore((s) => s.dismiss);
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    if (show) {
      clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => dismiss(), 4000);
    }
    return () => clearTimeout(timerRef.current);
  }, [show, message, status, dismiss]);

  if (!show) return null;
  const Icon = ICON[status];
  const accent = ACCENT[status];

  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-5 right-5 z-1000 flex items-center gap-3 px-4 py-3 rounded-lg border text-sm shadow-lg max-w-sm"
      style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--fg)' }}
    >
      <Icon size={16} aria-hidden style={{ color: accent, flexShrink: 0 }} />
      <span className="min-w-0">{message}</span>
      <button
        type="button"
        onClick={() => dismiss()}
        className="btn-ghost p-1 ml-auto -mr-1"
        aria-label={t('common.closeDialog')}
      >
        <X size={14} aria-hidden />
      </button>
    </div>
  );
}
