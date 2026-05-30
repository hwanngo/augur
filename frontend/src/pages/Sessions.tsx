import { useEffect, useState, useCallback } from 'react';
import { AlertTriangle, ShieldOff } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, apiDelete, ApiError } from '../lib/api';
import useAuthStore from '../store/auth';
import Dialog from '../components/Dialog';
import { useToast } from '../store/toast';

/* ──────────────────────────── Types ─────────────────────────────────────── */
export interface Session {
  id: string;
  created_at: string;
  last_seen: string;
  expires_at: string;
  current: boolean;
}

/* ──────────────────────────── Sessions page ─────────────────────────────── */
export default function Sessions() {
  const { t } = useTranslation();
  const logout = useAuthStore((s) => s.logout);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<Session | null>(null);
  const [revoking, setRevoking] = useState(false);
  const toast = useToast();

  const fetchSessions = useCallback(async () => {
    try {
      const data = await apiGet<Session[]>('/api/auth/sessions');
      setSessions(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('sessions.failedLoad'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => { void fetchSessions(); }, [fetchSessions]);

  const handleRevoke = async () => {
    if (!revokeTarget) return;
    setRevoking(true);
    const wasCurrent = revokeTarget.current;
    try {
      await apiDelete(`/api/auth/sessions/${revokeTarget.id}`);
      toast(t('sessions.toasts.revoked'));
      setRevokeTarget(null);
      if (wasCurrent) {
        void logout();
        return;
      }
      await fetchSessions();
    } catch (err) {
      toast(err instanceof ApiError ? err.message : t('sessions.toasts.failed'), 'error');
    } finally {
      setRevoking(false);
    }
  };

  function formatDate(iso: string) {
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  }

  return (
    <div className="w-full max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
        {t('sessions.title')}
      </h1>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('sessions.loading')}
          />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('sessions.loading')}
          </span>
        </div>
      )}

      {error && (
        <div
          className="rounded-xl border p-4 flex items-center gap-3"
          style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}
          role="alert"
        >
          <AlertTriangle size={16} aria-hidden />
          {error}
        </div>
      )}

      {!loading && !error && sessions.length === 0 && (
        <div className="text-center py-16">
          <p className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('sessions.empty')}
          </p>
        </div>
      )}

      {!loading && !error && sessions.length > 0 && (
        <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
          <table className="w-full min-w-[720px] text-sm" aria-label={t('sessions.title')}>
            <thead style={{ background: 'var(--panel)' }}>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['created', 'lastSeen', 'expires', 'status', 'actions'].map((col) => (
                  <th
                    key={col}
                    className="px-3 py-2.5 text-left text-xs font-medium whitespace-nowrap"
                    style={{ color: 'var(--muted)' }}
                  >
                    {t(`sessions.table.${col}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr
                  key={s.id}
                  className="transition-colors hover:bg-[#1e242c]"
                  style={{ borderBottom: '1px solid var(--border)' }}
                >
                  <td className="px-3 py-2.5 text-xs tabular-nums" style={{ color: 'var(--fg)' }}>
                    {formatDate(s.created_at)}
                  </td>
                  <td className="px-3 py-2.5 text-xs tabular-nums" style={{ color: 'var(--fg)' }}>
                    {formatDate(s.last_seen)}
                  </td>
                  <td className="px-3 py-2.5 text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                    {formatDate(s.expires_at)}
                  </td>
                  <td className="px-3 py-2.5">
                    {s.current && (
                      <span
                        className="px-2 py-0.5 rounded-full text-[11px] font-medium uppercase tracking-wide"
                        style={{ background: '#162920', color: '#3fb950' }}
                      >
                        {t('sessions.current')}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <button
                      type="button"
                      className="btn-ghost px-2 py-1 text-xs flex items-center gap-1"
                      style={{ color: '#ffb4ab' }}
                      onClick={() => setRevokeTarget(s)}
                      aria-label={`${t('sessions.revoke')} ${s.id}`}
                    >
                      <ShieldOff size={12} aria-hidden />
                      {t('sessions.revoke')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Dialog
        open={!!revokeTarget}
        title={t('sessions.revokeTitle')}
        message={t('sessions.revokeConfirm')}
        variant="destructive"
        confirmLabel={t('sessions.revoke')}
        loading={revoking}
        onClose={() => setRevokeTarget(null)}
        onConfirm={handleRevoke}
      />

    </div>
  );
}
