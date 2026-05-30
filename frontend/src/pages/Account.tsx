import { useState } from 'react';
import { Eye, EyeOff, KeyRound } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiPost, ApiError } from '../lib/api';
import useAuthStore from '../store/auth';
import { useToast } from '../store/toast';

/* ──────────────────────────── Field ─────────────────────────────────────── */
function Field({ id, label, error, children }: { id: string; label: string; error?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium" style={{ color: 'var(--muted)' }}>
        {label}
      </label>
      {children}
      {error && (
        <p className="text-xs" style={{ color: '#ffb4ab' }} role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

/* ─────────────────── Password input with show/hide ──────────────────────── */
function PasswordInput({
  id,
  value,
  onChange,
  placeholder,
  disabled,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  disabled?: boolean;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className="relative">
      <input
        id={id}
        type={show ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        autoComplete="new-password"
        className="w-full px-3 py-2 text-sm rounded-lg border pr-9 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
        style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
      />
      <button
        type="button"
        onClick={() => setShow((s) => !s)}
        className="absolute right-2 top-1/2 -translate-y-1/2 btn-ghost p-1"
        aria-label={show ? 'Hide password' : 'Show password'}
        tabIndex={0}
      >
        {show ? <EyeOff size={14} aria-hidden /> : <Eye size={14} aria-hidden />}
      </button>
    </div>
  );
}

/* ──────────────────────────── Account page ──────────────────────────────── */
export default function Account() {
  const { t } = useTranslation();
  const user = useAuthStore((s) => s.user);
  const role = useAuthStore((s) => s.role);

  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const toast = useToast();

  /* Inline validation */
  const newPwError = newPw && newPw.length < 12 ? t('account.hints.minLength') : undefined;
  const samePwError = newPw && currentPw && newPw === currentPw ? t('account.hints.newSame') : undefined;
  const confirmError = confirmPw && newPw !== confirmPw ? t('account.hints.confirmMatch') : undefined;

  const isValid =
    currentPw.length > 0 &&
    newPw.length >= 12 &&
    newPw !== currentPw &&
    newPw === confirmPw;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValid) return;
    setSubmitting(true);
    try {
      await apiPost('/api/auth/change-password', {
        current_password: currentPw,
        new_password: newPw,
      });
      toast(t('account.toasts.success'));
      setCurrentPw('');
      setNewPw('');
      setConfirmPw('');
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          toast(t('account.toasts.wrongCurrent'), 'error');
        } else if (err.status === 422) {
          toast(t('account.toasts.weakPassword'), 'error');
        } else {
          toast(t('account.toasts.failed'), 'error');
        }
      } else {
        toast(t('account.toasts.failed'), 'error');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
          {t('account.title')}
        </h1>
      </div>

      {/* User info card */}
      <div
        className="rounded-xl border p-4 flex items-center gap-3"
        style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
      >
        <div
          className="w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold uppercase flex-shrink-0"
          style={{ background: 'var(--accent)', color: '#0d1117' }}
          aria-hidden
        >
          {user?.[0] ?? '?'}
        </div>
        <div>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>
            {t('account.currentUser')}
          </p>
          <p className="font-semibold text-sm" style={{ color: 'var(--fg)' }}>
            {user}
          </p>
          <span
            className="px-2 py-0.5 rounded-full text-[11px] font-medium uppercase tracking-wide"
            style={{
              background: role === 'admin' ? '#7a4a00' : role === 'analyst' ? '#162920' : 'var(--panel)',
              color: role === 'admin' ? '#ffd28a' : role === 'analyst' ? '#3fb950' : 'var(--muted)',
            }}
          >
            {role}
          </span>
        </div>
      </div>

      {/* Change password form */}
      <div
        className="rounded-xl border p-5 space-y-5"
        style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
      >
        <div className="flex items-center gap-2">
          <KeyRound size={16} style={{ color: 'var(--accent)' }} aria-hidden />
          <h2 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
            {t('account.changePassword')}
          </h2>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} noValidate className="space-y-4">
          <Field id="current-password" label={t('account.fields.currentPassword')}>
            <PasswordInput
              id="current-password"
              value={currentPw}
              onChange={setCurrentPw}
              placeholder={t('account.placeholders.currentPassword')}
              disabled={submitting}
            />
          </Field>

          <Field
            id="new-password"
            label={t('account.fields.newPassword')}
            error={newPwError ?? samePwError}
          >
            <PasswordInput
              id="new-password"
              value={newPw}
              onChange={setNewPw}
              placeholder={t('account.placeholders.newPassword')}
              disabled={submitting}
            />
          </Field>

          <Field
            id="confirm-password"
            label={t('account.fields.confirmPassword')}
            error={confirmError}
          >
            <PasswordInput
              id="confirm-password"
              value={confirmPw}
              onChange={setConfirmPw}
              placeholder={t('account.placeholders.confirmPassword')}
              disabled={submitting}
            />
          </Field>

          <button
            type="submit"
            className="btn-primary w-full justify-center"
            disabled={!isValid || submitting}
          >
            {submitting ? t('account.submitting') : t('account.submit')}
          </button>
        </form>
      </div>

    </div>
  );
}
