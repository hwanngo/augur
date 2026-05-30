import { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Filter, AlertTriangle, Trash2, Info, VolumeX, ChevronDown } from 'lucide-react';
import { apiGet, apiPost, apiDelete, ApiError } from '../lib/api';
import useAuthStore, { type Role } from '../store/auth';
import Dropdown from '../components/Dropdown';
import { useToast } from '../store/toast';

const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

interface Entry {
  id: string; action: 'SUPPRESS' | 'DOWNGRADE'; downgrade_to: string | null; reason: string;
  author: string; scenario_id: string | null; technique: string | null; host: string | null;
  zone: string | null; process_regex: string | null; command_regex: string | null;
  image_regex: string | null; ts_from: string | null; ts_to: string | null; enabled: boolean;
  expires_at: string | null; source: string; source_alert_id: string | null; hit_count?: number;
}
interface SuppressedRec { scenario_id: string; name: string; severity: string; proximity: number;
  affected_hosts: string[]; entry_id: string; reason: string; action?: string;
  from_band?: string; to_band?: string; }
interface Ledger {
  ledger: { input_count: number; kept_count: number; suppressed_count: number;
    downgraded_count: number; active_entry_count: number };
  suppressed: SuppressedRec[]; downgraded: SuppressedRec[]; honesty_note: string;
}

interface BaselineHint { process: string; occurrences: number; host_count: number;
  single_host: boolean; first_seen: string; last_seen: string; honesty_note: string; }

const ACTIONS = ['SUPPRESS', 'DOWNGRADE'] as const;
const BANDS = ['WATCH', 'HIGH'] as const;
const EMPTY = { action: 'SUPPRESS', downgrade_to: 'WATCH', scenario_id: '', host: '', zone: '',
  technique: '', process_regex: '', command_regex: '', image_regex: '', reason: '' };

export default function Tuning() {
  const { t } = useTranslation();
  const toast = useToast();
  const role = useAuthStore((s) => s.role);
  const canEdit = role != null && ROLE_RANK[role] >= ROLE_RANK.analyst;

  const [entries, setEntries] = useState<Entry[]>([]);
  const [ledger, setLedger] = useState<Ledger | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ ...EMPTY });
  const [submitting, setSubmitting] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [hint, setHint] = useState<BaselineHint | null>(null);

  const refresh = useCallback(() => {
    apiGet<Entry[]>('/api/tuning').then(setEntries).catch(() => {});
    apiGet<Ledger>('/api/tuning/ledger').then(setLedger).catch(() => {});
  }, []);
  useEffect(() => { refresh(); }, [refresh]);

  // Prefill + open the form when arriving from an alert's "Propose allowlist (FP)" action.
  const location = useLocation();
  useEffect(() => {
    const state = location.state as { draft?: Record<string, unknown>; baselineHint?: BaselineHint | null } | null;
    const draft = state?.draft;
    if (!draft) return;
    setForm((f) => {
      const next = { ...f };
      for (const k of Object.keys(f) as (keyof typeof f)[]) {
        if (k in draft && draft[k] != null) next[k] = String(draft[k]);
      }
      return next;
    });
    setHint(state?.baselineHint ?? null);
    setShowForm(true);
    // Clear router state so a refresh/back doesn't re-trigger the prefill.
    window.history.replaceState({}, '');
  }, [location.state]);

  const set = (k: string, v: string) => setForm((f) => ({ ...f, [k]: v }));

  const create = async () => {
    setSubmitting(true); setError(null);
    // Only send non-empty predicates; the backend rejects a no-predicate entry.
    const body: Record<string, unknown> = { action: form.action, reason: form.reason.trim() };
    if (form.action === 'DOWNGRADE') body.downgrade_to = form.downgrade_to;
    for (const k of ['scenario_id', 'host', 'zone', 'technique', 'process_regex', 'command_regex', 'image_regex'] as const) {
      if (form[k].trim()) body[k] = form[k].trim();
    }
    try {
      await apiPost('/api/tuning', body);
      setForm({ ...EMPTY }); setShowForm(false); setHint(null); refresh();
      toast(t('tuning.created'), 'success');
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('tuning.createFailed'));
    } finally { setSubmitting(false); }
  };

  const toggle = async (e: Entry) => {
    await apiPost(`/api/tuning/${e.id}/${e.enabled ? 'disable' : 'enable'}`).catch(() => {});
    refresh();
  };
  const remove = async (e: Entry) => {
    await apiDelete(`/api/tuning/${e.id}`).catch(() => {});
    refresh();
  };

  const tunedOut = useMemo(() => {
    if (!ledger) return [];
    return [...ledger.suppressed.map((s) => ({ ...s, kind: 'SUPPRESS' as const })),
            ...ledger.downgraded.map((s) => ({ ...s, kind: 'DOWNGRADE' as const }))];
  }, [ledger]);

  return (
    <div className="w-full max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <Filter size={18} aria-hidden /> {t('tuning.title')}
          </h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{t('tuning.subtitle')}</p>
        </div>
        {canEdit && (
          <button type="button" onClick={() => { setShowForm((s) => !s); setHint(null); }}
                  className="btn-primary px-3 py-1.5 text-xs rounded-lg">
            {showForm ? t('tuning.cancel') : t('tuning.newEntry')}
          </button>
        )}
      </div>

      {/* Honesty banner */}
      {ledger && (
        <div className="rounded-xl border px-3 py-2 flex items-start gap-2 text-xs"
             style={{ background: '#1a2230', borderColor: '#3b5572', color: '#9fc3ff' }} role="note">
          <Info size={14} aria-hidden className="flex-shrink-0 mt-0.5" /> <span>{ledger.honesty_note}</span>
        </div>
      )}

      {error && (
        <div className="rounded-xl border p-3 flex items-center gap-2 text-sm" role="alert"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}>
          <AlertTriangle size={14} aria-hidden /> {error}
        </div>
      )}

      {/* Create form */}
      {canEdit && showForm && (
        <div className="rounded-xl border p-4 space-y-3" style={{ borderColor: 'var(--border)', background: 'var(--panel)' }}>
          {hint && (
            <div className="rounded-lg border px-3 py-2 text-xs" style={{ borderColor: '#3b5572', background: '#161f2e', color: '#9fc3ff' }}>
              <span style={{ color: 'var(--fg)' }}>
                {t('tuning.baselineHint', { process: hint.process, occurrences: hint.occurrences, hosts: hint.host_count })}
                {hint.single_host ? ` ${t('tuning.baselineSingleHost')}` : ''}
              </span>
              <span className="block mt-0.5 italic" style={{ color: 'var(--muted)' }}>{hint.honesty_note}</span>
            </div>
          )}
          <div className="flex flex-wrap gap-3">
            <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
              {t('tuning.action')}
              <Dropdown aria-label={t('tuning.action')} value={form.action} onChange={(v) => set('action', v)}
                        options={ACTIONS.map((a) => ({ value: a, label: a }))} />
            </label>
            {form.action === 'DOWNGRADE' && (
              <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
                {t('tuning.downgradeTo')}
                <Dropdown aria-label={t('tuning.downgradeTo')} value={form.downgrade_to} onChange={(v) => set('downgrade_to', v)}
                          options={BANDS.map((b) => ({ value: b, label: b }))} />
              </label>
            )}
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {([['scenario_id', 'tuning.scenarioId'], ['host', 'tuning.host'], ['zone', 'tuning.zone'],
               ['technique', 'tuning.technique'], ['process_regex', 'tuning.processRegex'],
               ['command_regex', 'tuning.commandRegex']] as const).map(([k, label]) => (
              <label key={k} className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
                {t(label)}
                <input value={form[k]} onChange={(e) => set(k, e.target.value)}
                       className="rounded-lg border px-2 py-1.5 text-xs"
                       style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }} />
              </label>
            ))}
          </div>
          <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
            {t('tuning.reason')} *
            <input value={form.reason} onChange={(e) => set('reason', e.target.value)}
                   placeholder={t('tuning.reasonPlaceholder')}
                   className="rounded-lg border px-2 py-1.5 text-xs"
                   style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }} />
          </label>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('tuning.predicateHint')}</p>
          <button type="button" onClick={create} disabled={submitting || !form.reason.trim()}
                  className="btn-primary px-3 py-1.5 text-xs rounded-lg">
            {submitting ? t('tuning.saving') : t('tuning.save')}
          </button>
        </div>
      )}

      {/* Entries */}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
          {t('tuning.entries')} ({entries.length})
        </h2>
        {entries.length === 0 && (
          <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('tuning.noEntries')}</p>
        )}
        <ul className="space-y-1.5">
          {entries.map((e) => (
            <li key={e.id} className="rounded-lg border px-3 py-2 flex items-center gap-3 text-xs"
                style={{ borderColor: 'var(--border)', background: 'var(--panel)', opacity: e.enabled ? 1 : 0.55 }}>
              <span className="px-2 py-0.5 rounded-full font-bold uppercase tracking-wide flex-shrink-0"
                    style={{ background: e.action === 'SUPPRESS' ? '#71221c' : '#7a4a00',
                             color: e.action === 'SUPPRESS' ? '#ffb4ab' : '#ffd28a' }}>
                {e.action === 'SUPPRESS' ? t('tuning.suppress') : `${t('tuning.downgrade')}→${e.downgrade_to}`}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate" style={{ color: 'var(--fg)' }}>{e.reason}</span>
                <span className="block truncate" style={{ color: 'var(--muted)' }}>
                  {[e.scenario_id, e.technique, e.host, e.zone, e.process_regex && `proc~${e.process_regex}`,
                    e.command_regex && `cmd~${e.command_regex}`].filter(Boolean).join(' · ')}
                  {' · '}{t('tuning.by', { author: e.author })}
                </span>
              </span>
              <span className="tabular-nums flex-shrink-0" style={{ color: 'var(--muted)' }}
                    title={t('tuning.hitCountTitle')}>
                {t('tuning.hits', { count: e.hit_count ?? 0 })}
              </span>
              {canEdit && (
                <>
                  <button type="button" onClick={() => toggle(e)}
                          className="px-2 py-1 rounded border flex-shrink-0"
                          style={{ borderColor: 'var(--border)', color: 'var(--muted)' }}>
                    {e.enabled ? t('tuning.disable') : t('tuning.enable')}
                  </button>
                  <button type="button" onClick={() => remove(e)} aria-label={t('tuning.delete')}
                          className="p-1 rounded flex-shrink-0" style={{ color: '#ff8a80' }}>
                    <Trash2 size={14} />
                  </button>
                </>
              )}
            </li>
          ))}
        </ul>
      </section>

      {/* Tuned-out ledger (always-visible honesty surface) */}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <VolumeX size={15} aria-hidden /> {t('tuning.tunedOut')}
          {ledger && <span className="font-normal" style={{ color: 'var(--muted)' }}>
            ({ledger.ledger.suppressed_count} {t('tuning.suppressedN')}, {ledger.ledger.downgraded_count} {t('tuning.downgradedN')})
          </span>}
        </h2>
        {tunedOut.length === 0 ? (
          <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('tuning.nothingTuned')}</p>
        ) : (
          <ul className="space-y-1">
            {tunedOut.map((s, i) => (
              <li key={`${s.scenario_id}-${i}`} className="rounded-lg border px-3 py-1.5 text-xs flex items-center gap-2"
                  style={{ borderColor: 'var(--border)', background: 'var(--panel)' }}>
                <ChevronDown size={13} aria-hidden style={{ color: s.kind === 'SUPPRESS' ? '#ff8a80' : '#ffd28a' }} />
                <span className="flex-1 min-w-0 truncate" style={{ color: 'var(--fg)' }}>
                  {s.scenario_id} · {s.name}
                  {s.kind === 'DOWNGRADE' && ` (${s.from_band}→${s.to_band})`}
                </span>
                <span className="truncate flex-shrink-0" style={{ color: 'var(--muted)', maxWidth: '40%' }}
                      title={s.reason}>{s.reason}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
