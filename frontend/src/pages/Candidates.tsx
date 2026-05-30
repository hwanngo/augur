import { useEffect, useState, useCallback } from 'react';
import {
  Sparkles, Eye, Check, X, Loader2,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, apiPost, ApiError } from '../lib/api';
import useAuthStore, { type Role } from '../store/auth';
import SharedDialog from '../components/Dialog';
import { useToast } from '../store/toast';

/* ────────────────────────────────── Types ─────────────────────────────── */
export interface Candidate {
  id: string;
  scenario_id: string;
  category: string;
  status: 'pending' | 'approved' | 'rejected';
  plausibility: number;
  seed_id: string;
  mutation_axes: string;
  created_by: string;
  created_at: string;
  reviewed_by: string;
  reviewed_at: string;
  yaml: string;
  gauntlet_report: string;
}

interface GenerateResponse {
  requested: number;
  passed: number;
  candidates: { scenario_id: string; passed: boolean; reject_stage: string; reason: string; plausibility: number; notes: string[] }[];
}

type StatusFilter = 'all' | 'pending' | 'approved' | 'rejected';

const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

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
      className="w-full px-3 py-2 text-sm rounded-lg border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
      style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
    />
  );
}

/* ───────────────────────────── Status badge ────────────────────────────── */
function StatusBadge({ status }: { status: Candidate['status'] }) {
  const { t } = useTranslation();
  const styles: Record<Candidate['status'], { bg: string; fg: string }> = {
    pending: { bg: '#3a2e00', fg: '#ffd28a' },
    approved: { bg: '#162920', fg: '#3fb950' },
    rejected: { bg: '#2a1a1a', fg: '#ffb4ab' },
  };
  const s = styles[status];
  return (
    <span
      className="px-2 py-0.5 rounded-full text-[11px] font-medium uppercase tracking-wide"
      style={{ background: s.bg, color: s.fg }}
    >
      {t(`candidates.status.${status}`)}
    </span>
  );
}

/* ───────────────────────────── Candidates page ─────────────────────────── */
export default function CandidatesPage() {
  const { t } = useTranslation();
  const role = useAuthStore((s) => s.role);
  const isAdmin = role != null && ROLE_RANK[role] >= ROLE_RANK.admin;

  const [items, setItems] = useState<Candidate[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<StatusFilter>('all');
  const showToast = useToast();

  const [genOpen, setGenOpen] = useState(false);
  const [detail, setDetail] = useState<Candidate | null>(null);
  const [rejectTarget, setRejectTarget] = useState<Candidate | null>(null);
  const [dialogLoading, setDialogLoading] = useState(false);

  const [genForm, setGenForm] = useState({ seed: '', category: '', n: 5, axes: '' });
  const [rejectReason, setRejectReason] = useState('');

  const fetchCandidates = useCallback(async () => {
    try {
      const data = await apiGet<Candidate[]>('/api/candidates');
      setItems(data);
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('candidates.toasts.failedLoad'), 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast, t]);

  useEffect(() => { void fetchCandidates(); }, [fetchCandidates]);

  const visible = filter === 'all' ? items : items.filter((c) => c.status === filter);

  /* Actions */
  const handleGenerate = async () => {
    setDialogLoading(true);
    try {
      const axes = genForm.axes.split(',').map((a) => a.trim()).filter(Boolean);
      const res = await apiPost<GenerateResponse>('/api/generate', {
        seed: genForm.seed || undefined,
        category: genForm.category || undefined,
        n: genForm.n,
        axes,
      });
      showToast(t('candidates.toasts.generated', { passed: res.passed, requested: res.requested }));
      setGenOpen(false);
      setGenForm({ seed: '', category: '', n: 5, axes: '' });
      await fetchCandidates();
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('candidates.toasts.failedGenerate'), 'error');
    } finally {
      setDialogLoading(false);
    }
  };

  const handleApprove = async (c: Candidate) => {
    setDialogLoading(true);
    try {
      await apiPost(`/api/candidates/${c.id}/approve`);
      showToast(t('candidates.toasts.approved', { id: c.scenario_id }));
      setDetail(null);
      await fetchCandidates();
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('candidates.toasts.failedApprove'), 'error');
    } finally {
      setDialogLoading(false);
    }
  };

  const handleReject = async () => {
    if (!rejectTarget) return;
    setDialogLoading(true);
    try {
      await apiPost(`/api/candidates/${rejectTarget.id}/reject`, { reason: rejectReason });
      showToast(t('candidates.toasts.rejected', { id: rejectTarget.scenario_id }));
      setRejectTarget(null);
      setRejectReason('');
      setDetail(null);
      await fetchCandidates();
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : t('candidates.toasts.failedReject'), 'error');
    } finally {
      setDialogLoading(false);
    }
  };

  const reportNotes = (raw: string): string[] => {
    try {
      const parsed = JSON.parse(raw) as { notes?: string[] };
      return parsed.notes ?? [];
    } catch {
      return [];
    }
  };

  const FILTERS: StatusFilter[] = ['all', 'pending', 'approved', 'rejected'];

  return (
    <div className="w-full max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{t('candidates.title')}</h1>
          <p className="text-xs mt-1 max-w-2xl" style={{ color: 'var(--muted)' }}>{t('candidates.subtitle')}</p>
        </div>
        {isAdmin && (
          <button type="button" className="btn-primary flex-shrink-0" onClick={() => setGenOpen(true)}>
            <Sparkles size={14} aria-hidden />
            {t('candidates.generate')}
          </button>
        )}
      </div>

      {/* Status filter tabs */}
      <div className="flex items-center gap-1" role="tablist" aria-label={t('candidates.table.status')}>
        {FILTERS.map((f) => (
          <button
            key={f}
            type="button"
            role="tab"
            aria-selected={filter === f}
            onClick={() => setFilter(f)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
            style={{
              background: filter === f ? 'var(--accent)' : 'transparent',
              color: filter === f ? '#0d1117' : 'var(--muted)',
            }}
          >
            {t(`candidates.filters.${f}`)}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('candidates.loading')}
          />
        </div>
      ) : (
        <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
          <table className="w-full min-w-[720px] text-sm" aria-label={t('candidates.title')}>
            <thead style={{ background: 'var(--panel)' }}>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['scenarioId', 'category', 'plausibility', 'status', 'seed', 'createdBy', 'created', 'actions'].map((c) => (
                  <th key={c} className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>
                    {t(`candidates.table.${c}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map((c) => (
                <tr key={c.id} className="transition-colors hover:bg-[#1e242c]" style={{ borderBottom: '1px solid var(--border)' }}>
                  <td className="px-3 py-2.5 font-medium font-mono text-xs" style={{ color: 'var(--fg)' }}>{c.scenario_id}</td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--muted)' }}>{c.category}</td>
                  <td className="px-3 py-2.5 tabular-nums text-xs" style={{ color: 'var(--fg)' }}>{c.plausibility.toFixed(2)}</td>
                  <td className="px-3 py-2.5"><StatusBadge status={c.status} /></td>
                  <td className="px-3 py-2.5 font-mono text-xs" style={{ color: 'var(--muted)' }}>{c.seed_id || '—'}</td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--muted)' }}>{c.created_by}</td>
                  <td className="px-3 py-2.5 text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                    {c.created_at ? new Date(c.created_at).toLocaleDateString() : '—'}
                  </td>
                  <td className="px-3 py-2.5">
                    <button
                      type="button"
                      className="btn-ghost px-2 py-1 text-xs"
                      onClick={() => setDetail(c)}
                      aria-label={t('candidates.actions.view', { id: c.scenario_id })}
                      title={t('candidates.actions.view', { id: c.scenario_id })}
                    >
                      <Eye size={12} aria-hidden />
                    </button>
                  </td>
                </tr>
              ))}
              {visible.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-3 py-8 text-center text-sm" style={{ color: 'var(--muted)' }}>
                    {t('candidates.empty')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Generate dialog (admin) */}
      <SharedDialog
        open={genOpen}
        title={t('candidates.generateTitle')}
        confirmLabel={t('candidates.generate')}
        loading={dialogLoading}
        onClose={() => setGenOpen(false)}
        onConfirm={handleGenerate}
      >
        <div className="space-y-4">
          <Field label={t('candidates.fields.seed')}>
            <Input
              type="text" value={genForm.seed}
              // Focus-on-open: first field of the generate dialog; focusing it on open is the expected modal UX.
              // eslint-disable-next-line jsx-a11y/no-autofocus
              autoFocus
              onChange={(e) => setGenForm((g) => ({ ...g, seed: e.target.value }))}
              placeholder={t('candidates.fields.seedPlaceholder')}
            />
          </Field>
          <Field label={t('candidates.fields.category')}>
            <Input
              type="text" value={genForm.category}
              onChange={(e) => setGenForm((g) => ({ ...g, category: e.target.value }))}
              placeholder={t('candidates.fields.categoryPlaceholder')}
            />
          </Field>
          <Field label={t('candidates.fields.count')}>
            <Input
              type="number" min={1} max={10} value={genForm.n}
              onChange={(e) => setGenForm((g) => ({ ...g, n: Number(e.target.value) }))}
            />
          </Field>
          <Field label={t('candidates.fields.axes')}>
            <Input
              type="text" value={genForm.axes}
              onChange={(e) => setGenForm((g) => ({ ...g, axes: e.target.value }))}
              placeholder={t('candidates.fields.axesPlaceholder')}
            />
          </Field>
        </div>
      </SharedDialog>

      {/* Detail dialog */}
      <SharedDialog
        open={!!detail}
        wide
        title={detail ? t('candidates.detailTitle', { id: detail.scenario_id }) : ''}
        onClose={() => setDetail(null)}
      >
        {detail && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-4 text-xs" style={{ color: 'var(--muted)' }}>
              <StatusBadge status={detail.status} />
              <span>{t('candidates.detail.plausibility')}: <span style={{ color: 'var(--fg)' }} className="tabular-nums">{detail.plausibility.toFixed(2)}</span></span>
              <span>{t('candidates.detail.seed')}: <span className="font-mono" style={{ color: 'var(--fg)' }}>{detail.seed_id || '—'}</span></span>
              {detail.mutation_axes && <span>{t('candidates.detail.axes')}: <span style={{ color: 'var(--fg)' }}>{detail.mutation_axes}</span></span>}
              {detail.reviewed_by && <span>{t('candidates.detail.reviewedBy', { user: detail.reviewed_by })}</span>}
            </div>

            <div>
              <div className="text-xs font-medium mb-1" style={{ color: 'var(--muted)' }}>{t('candidates.detail.report')}</div>
              {reportNotes(detail.gauntlet_report).length > 0 ? (
                <ul className="list-disc list-inside text-xs space-y-0.5" style={{ color: 'var(--fg)' }}>
                  {reportNotes(detail.gauntlet_report).map((n, i) => <li key={i}>{n}</li>)}
                </ul>
              ) : (
                <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('candidates.detail.noNotes')}</p>
              )}
            </div>

            <div>
              <div className="text-xs font-medium mb-1" style={{ color: 'var(--muted)' }}>{t('candidates.detail.yaml')}</div>
              <pre
                className="text-xs rounded-lg border p-3 overflow-auto max-h-80 font-mono leading-relaxed"
                style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
              >{detail.yaml}</pre>
            </div>

            {isAdmin && detail.status === 'pending' && (
              <div className="flex gap-3 justify-end pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                <button
                  type="button" className="btn-danger" disabled={dialogLoading}
                  onClick={() => { setRejectTarget(detail); setRejectReason(''); }}
                >
                  <X size={14} aria-hidden />{t('candidates.actions.reject')}
                </button>
                <button
                  type="button" className="btn-primary" disabled={dialogLoading}
                  onClick={() => void handleApprove(detail)}
                >
                  {dialogLoading ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <Check size={14} aria-hidden />}
                  {t('candidates.actions.approve')}
                </button>
              </div>
            )}
          </div>
        )}
      </SharedDialog>

      {/* Reject reason dialog */}
      <SharedDialog
        open={!!rejectTarget}
        title={t('candidates.rejectTitle')}
        confirmLabel={t('candidates.actions.reject')}
        variant="destructive"
        loading={dialogLoading}
        onClose={() => setRejectTarget(null)}
        onConfirm={handleReject}
      >
        <Field label={t('candidates.fields.reason')}>
          <Input
            type="text" value={rejectReason}
            // Focus-on-open: sole field of the reject dialog; focusing it on open is the expected modal UX.
            // eslint-disable-next-line jsx-a11y/no-autofocus
            autoFocus
            onChange={(e) => setRejectReason(e.target.value)}
            placeholder={t('candidates.fields.reasonPlaceholder')}
          />
        </Field>
      </SharedDialog>

    </div>
  );
}
