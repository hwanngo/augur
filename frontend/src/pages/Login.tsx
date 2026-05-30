import { useEffect, useRef, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Loader2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import useAuthStore from '../store/auth';
import { setNavigate } from '../store/auth';
import { ApiError } from '../lib/api';

export default function Login() {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const usernameRef = useRef<HTMLInputElement>(null);

  const login = useAuthStore((s) => s.login);
  const status = useAuthStore((s) => s.status);
  const navigate = useNavigate();
  const location = useLocation();

  setNavigate(navigate);

  const from = (location.state as { from?: { pathname: string } } | null)?.from?.pathname ?? '/dashboard';

  // If already authed, redirect
  useEffect(() => {
    if (status === 'authed') {
      navigate(from, { replace: true });
    }
  }, [status, navigate, from]);

  // Focus first field on mount
  useEffect(() => {
    usernameRef.current?.focus();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setPending(true);
    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setError(t('login.errors.invalidCredentials'));
        } else if (err.status === 429) {
          setError(t('login.errors.lockedOut'));
        } else {
          setError(t('login.errors.generic', { status: err.status }));
        }
      } else {
        setError(t('login.errors.network'));
      }
    } finally {
      setPending(false);
    }
  };

  return (
    <div
      className="flex min-h-screen items-center justify-center px-4"
      style={{ background: 'var(--bg)' }}
    >
      <div
        className="w-full max-w-sm rounded-xl border p-8 space-y-6"
        style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
      >
        {/* Logo */}
        <div className="flex items-center justify-center gap-2">
          <Shield size={28} style={{ color: 'var(--accent)' }} aria-hidden />
          <span className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>
            {t('nav.appName')}
          </span>
        </div>

        <h1 className="text-center text-sm font-medium" style={{ color: 'var(--muted)' }}>
          {t('login.title')}
        </h1>

        <form onSubmit={(e) => void handleSubmit(e)} noValidate className="space-y-4">
          <div className="flex flex-col gap-1">
            <label
              htmlFor="username"
              className="text-xs font-medium"
              style={{ color: 'var(--muted)' }}
            >
              {t('login.username')}
            </label>
            <input
              ref={usernameRef}
              id="username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={pending}
              className="w-full px-3 py-2 text-sm rounded-lg border transition-colors"
              style={{
                background: 'var(--bg)',
                borderColor: 'var(--border)',
                color: 'var(--fg)',
              }}
            />
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor="password"
              className="text-xs font-medium"
              style={{ color: 'var(--muted)' }}
            >
              {t('login.password')}
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={pending}
              className="w-full px-3 py-2 text-sm rounded-lg border transition-colors"
              style={{
                background: 'var(--bg)',
                borderColor: 'var(--border)',
                color: 'var(--fg)',
              }}
            />
          </div>

          {/* Error region (aria-live) */}
          <div
            role="alert"
            aria-live="polite"
            className="min-h-[1.25rem]"
          >
            {error && (
              <p className="text-xs" style={{ color: '#ffb4ab' }}>
                {error}
              </p>
            )}
          </div>

          <button
            type="submit"
            disabled={pending || !username || !password}
            className="btn-primary w-full justify-center"
          >
            {pending ? (
              <>
                <Loader2 size={14} className="animate-spin" aria-hidden />
                {t('login.signingIn')}
              </>
            ) : (
              t('login.signIn')
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
