import { useEffect, useState, useCallback } from 'react';
import {
  UserPlus, Trash2, KeyRound, ChevronUp, ChevronDown, Minus, Plus,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, apiPost, apiPatch, apiDelete, ApiError } from '../lib/api';
import SharedDialog from '../components/Dialog';
import { useConfirm } from '../components/useConfirm';
import Dropdown from '../components/Dropdown';
import { useToast } from '../store/toast';

/* ────────────────────────────────── Types ─────────────────────────────── */
export interface User {
  id: number;
  username: string;
  role: string;
  disabled: boolean;
  created_at: string;
  updated_at: string;
}

type SortKey = keyof User;
type SortDir = 'asc' | 'desc';

/* ─────────────────────────── Field helpers ─────────────────────────────── */
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs font-medium" style={{ color: 'var(--muted)' }}>{label}</label>
      {children}
    </div>
  );
}

function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className="w-full px-3 py-2 text-sm rounded-lg border transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
      style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
    />
  );
}

function RoleSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation();
  return (
    <Dropdown
      value={value}
      onChange={onChange}
      aria-label={t('users.fields.role')}
      options={[
        { value: 'viewer', label: 'viewer' },
        { value: 'analyst', label: 'analyst' },
        { value: 'admin', label: 'admin' },
      ]}
    />
  );
}

/* ───────────────────────────── Users page ──────────────────────────────── */
export default function UsersPage() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>('id');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const showToast = useToast();

  // Dialogs
  const [createOpen, setCreateOpen] = useState(false);
  const [resetTarget, setResetTarget] = useState<User | null>(null);
  const [editTarget, setEditTarget] = useState<User | null>(null);
  const [dialogLoading, setDialogLoading] = useState(false);

  // Create form
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'viewer' });

  // Reset form
  const [newPassword, setNewPassword] = useState('');

  const fetchUsers = useCallback(async () => {
    try {
      const data = await apiGet<User[]>('/api/users');
      setUsers(data);
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('users.toasts.failedLoad'), 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast, t]);

  useEffect(() => { void fetchUsers(); }, [fetchUsers]);

  /* Sorting */
  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir('asc'); }
  };

  const sorted = [...users].sort((a, b) => {
    const av = a[sortKey];
    const bv = b[sortKey];
    const cmp = String(av) < String(bv) ? -1 : String(av) > String(bv) ? 1 : 0;
    return sortDir === 'asc' ? cmp : -cmp;
  });

  /* Actions */
  const handleCreate = async () => {
    setDialogLoading(true);
    try {
      await apiPost('/api/users', newUser);
      showToast(t('users.toasts.created', { username: newUser.username }));
      setCreateOpen(false);
      setNewUser({ username: '', password: '', role: 'viewer' });
      await fetchUsers();
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('users.toasts.failedCreate'), 'error');
    } finally {
      setDialogLoading(false);
    }
  };

  const handleDelete = async (u: User) => {
    if (
      !(await confirm({
        title: t('common.deleteConfirmTitle'),
        message: t('users.deleteConfirm', { name: u.username }),
        confirmLabel: t('common.delete'),
      }))
    )
      return;
    try {
      await apiDelete(`/api/users/${u.id}`);
      showToast(t('users.toasts.deleted', { username: u.username }));
      await fetchUsers();
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('users.toasts.failedDelete'), 'error');
    }
  };

  const handleReset = async () => {
    if (!resetTarget) return;
    setDialogLoading(true);
    try {
      await apiPost(`/api/users/${resetTarget.id}/reset-password`, { password: newPassword });
      showToast(t('users.toasts.passwordReset'));
      setResetTarget(null);
      setNewPassword('');
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('users.toasts.failedReset'), 'error');
    } finally {
      setDialogLoading(false);
    }
  };

  const handleToggleDisabled = async (u: User) => {
    try {
      await apiPatch(`/api/users/${u.id}`, { disabled: !u.disabled });
      showToast(
        u.disabled
          ? t('users.toasts.enabled', { username: u.username })
          : t('users.toasts.disabled', { username: u.username })
      );
      await fetchUsers();
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('users.toasts.failedUpdate'), 'error');
    }
  };

  const handleEditRole = async () => {
    if (!editTarget) return;
    setDialogLoading(true);
    try {
      await apiPatch(`/api/users/${editTarget.id}`, { role: editTarget.role });
      showToast(t('users.toasts.roleUpdated', { role: editTarget.role }));
      setEditTarget(null);
      await fetchUsers();
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('users.toasts.failedRole'), 'error');
    } finally {
      setDialogLoading(false);
    }
  };

  /* Sort header */
  function SortIcon({ col }: { col: SortKey }) {
    if (sortKey !== col) return <Minus size={12} className="opacity-30" aria-hidden />;
    return sortDir === 'asc'
      ? <ChevronUp size={12} aria-hidden />
      : <ChevronDown size={12} aria-hidden />;
  }

  function Th({ col, label }: { col: SortKey; label: string }) {
    return (
      <th
        className="px-3 py-2.5 text-left text-xs font-medium cursor-pointer select-none whitespace-nowrap transition-colors hover:text-(--fg)"
        style={{ color: 'var(--muted)' }}
        onClick={() => handleSort(col)}
        aria-sort={sortKey === col ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}
      >
        <span className="flex items-center gap-1">
          {label} <SortIcon col={col} />
        </span>
      </th>
    );
  }

  return (
    <div className="w-full max-w-(--breakpoint-2xl) mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
          {t('users.title')}
        </h1>
        <button
          type="button"
          className="btn-primary"
          onClick={() => setCreateOpen(true)}
          aria-label={t('users.createTitle')}
        >
          <UserPlus size={14} aria-hidden />
          {t('users.newUser')}
        </button>
      </div>

      {loading ? (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('users.loading')}
          />
        </div>
      ) : (
        <div
          className="rounded-xl border overflow-x-auto"
          style={{ borderColor: 'var(--border)' }}
        >
          <table className="w-full min-w-[720px] text-sm" aria-label={t('users.title')}>
            <thead style={{ background: 'var(--panel)' }}>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <Th col="id" label={t('users.table.id')} />
                <Th col="username" label={t('users.table.username')} />
                <Th col="role" label={t('users.table.role')} />
                <Th col="disabled" label={t('users.table.status')} />
                <Th col="created_at" label={t('users.table.created')} />
                <th className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>
                  {t('users.table.actions')}
                </th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((u) => (
                <tr
                  key={u.id}
                  className="transition-colors hover:bg-[#1e242c]"
                  style={{ borderBottom: '1px solid var(--border)' }}
                >
                  <td className="px-3 py-2.5 tabular-nums text-xs" style={{ color: 'var(--muted)' }}>
                    {u.id}
                  </td>
                  <td className="px-3 py-2.5 font-medium" style={{ color: 'var(--fg)' }}>
                    {u.username}
                  </td>
                  <td className="px-3 py-2.5">
                    <span
                      className="px-2 py-0.5 rounded-full text-[11px] font-medium uppercase tracking-wide"
                      style={{
                        background: u.role === 'admin' ? '#7a4a00' : u.role === 'analyst' ? '#162920' : 'var(--panel)',
                        color: u.role === 'admin' ? '#ffd28a' : u.role === 'analyst' ? '#3fb950' : 'var(--muted)',
                      }}
                    >
                      {u.role}
                    </span>
                  </td>
                  <td className="px-3 py-2.5">
                    <span
                      className="text-xs"
                      style={{ color: u.disabled ? '#ffb4ab' : 'var(--accent)' }}
                    >
                      {u.disabled ? t('users.status.disabled') : t('users.status.active')}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-1">
                      {/* Toggle enabled/disabled */}
                      <button
                        type="button"
                        className="btn-ghost px-2 py-1 text-xs"
                        onClick={() => void handleToggleDisabled(u)}
                        aria-label={u.disabled ? t('users.actions.enable', { username: u.username }) : t('users.actions.disable', { username: u.username })}
                        title={u.disabled ? t('users.status.active') : t('users.status.disabled')}
                      >
                        {u.disabled ? <Plus size={12} aria-hidden /> : <Minus size={12} aria-hidden />}
                      </button>
                      {/* Change role */}
                      <button
                        type="button"
                        className="btn-ghost px-2 py-1 text-xs"
                        onClick={() => setEditTarget({ ...u })}
                        aria-label={t('users.actions.changeRole', { username: u.username })}
                        title={t('users.actions.role')}
                      >
                        {t('users.actions.role')}
                      </button>
                      {/* Reset password */}
                      <button
                        type="button"
                        className="btn-ghost px-2 py-1 text-xs"
                        onClick={() => { setResetTarget(u); setNewPassword(''); }}
                        aria-label={t('users.actions.resetPassword', { username: u.username })}
                        title={t('users.actions.resetPassword', { username: u.username })}
                      >
                        <KeyRound size={12} aria-hidden />
                      </button>
                      {/* Delete */}
                      <button
                        type="button"
                        className="btn-ghost px-2 py-1 text-xs"
                        style={{ color: '#ffb4ab' }}
                        onClick={() => void handleDelete(u)}
                        aria-label={t('users.actions.delete', { username: u.username })}
                        title={t('common.delete')}
                      >
                        <Trash2 size={12} aria-hidden />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-sm" style={{ color: 'var(--muted)' }}>
                    {t('users.empty')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Create dialog */}
      <SharedDialog
        open={createOpen}
        title={t('users.createTitle')}
        confirmLabel={t('common.create')}
        loading={dialogLoading}
        onClose={() => setCreateOpen(false)}
        onConfirm={handleCreate}
      >
        <div className="space-y-4">
          <Field label={t('users.fields.username')}>
            <Input
              type="text"
              value={newUser.username}
              onChange={(e) => setNewUser((u) => ({ ...u, username: e.target.value }))}
              // Focus-on-open: first field of the create-user dialog; focusing it on open is the expected modal UX.
              // eslint-disable-next-line jsx-a11y/no-autofocus
              autoFocus
              placeholder={t('users.fields.usernamePlaceholder')}
            />
          </Field>
          <Field label={t('users.fields.password')}>
            <Input
              type="password"
              value={newUser.password}
              onChange={(e) => setNewUser((u) => ({ ...u, password: e.target.value }))}
              placeholder={t('users.fields.passwordPlaceholder')}
            />
            <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
              {t('users.fields.passwordHint')}
            </p>
          </Field>
          <Field label={t('users.fields.role')}>
            <RoleSelect value={newUser.role} onChange={(v) => setNewUser((u) => ({ ...u, role: v }))} />
          </Field>
        </div>
      </SharedDialog>

      {/* Reset password */}
      <SharedDialog
        open={!!resetTarget}
        title={t('users.resetPasswordTitle', { username: resetTarget?.username ?? '' })}
        confirmLabel={t('common.reset')}
        loading={dialogLoading}
        onClose={() => setResetTarget(null)}
        onConfirm={handleReset}
      >
        <Field label={t('users.fields.newPassword')}>
          <Input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            // Focus-on-open: sole field of the reset-password dialog; focusing it on open is the expected modal UX.
            // eslint-disable-next-line jsx-a11y/no-autofocus
            autoFocus
            placeholder={t('users.fields.passwordPlaceholder')}
          />
        </Field>
      </SharedDialog>

      {/* Edit role */}
      <SharedDialog
        open={!!editTarget}
        title={t('users.editRoleTitle', { username: editTarget?.username ?? '' })}
        confirmLabel={t('common.save')}
        loading={dialogLoading}
        onClose={() => setEditTarget(null)}
        onConfirm={handleEditRole}
      >
        <Field label={t('users.fields.role')}>
          <RoleSelect
            value={editTarget?.role ?? 'viewer'}
            onChange={(v) => setEditTarget((u) => u ? { ...u, role: v } : u)}
          />
        </Field>
      </SharedDialog>

    </div>
  );
}
