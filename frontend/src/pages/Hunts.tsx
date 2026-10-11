import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Telescope, AlertTriangle, Eye, Trash2, FileText, Info } from 'lucide-react';
import { apiGet, apiPost, apiPatch, apiDelete, ApiError } from '../lib/api';
import useAuthStore, { type Role } from '../store/auth';
import { useConfirm } from '../components/useConfirm';
import Dropdown from '../components/Dropdown';
import TimeRangePicker, { type TimeRange } from '../components/TimeRangePicker';
import { formatCriteria, formatTemporal, formatStall, type Temporal, type Stall } from '../lib/nextStep';
import { useToast } from '../store/toast';

export type HuntStatus = 'open' | 'investigating' | 'confirmed' | 'refuted' | 'abandoned';
const HUNT_STATUSES: HuntStatus[] = ['open', 'investigating', 'confirmed', 'refuted', 'abandoned'];
const TERMINAL_STATUSES = new Set<HuntStatus>(['confirmed', 'refuted']);

export interface HuntScope {
  scenario_ids?: string[];
  tactic?: string;
  zone?: string;
  host?: string;
  from?: string;
  to?: string;
}

export interface Hunt {
  id: string;
  owner: string;
  hypothesis: string;
  scope: HuntScope;
  status: HuntStatus;
  verdict_note: string;
  notes: string;
  verdict_evidence_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface NextStep {
  step_id: number;
  name?: string;
  matching_criteria?: Record<string, unknown>;
  temporal?: Temporal | null;
}

export interface EvidenceRow {
  scenario_id: string;
  name: string;
  severity: string;
  proximity: number;
  matched_count: number;
  total_steps: number;
  matched_steps: { step_id?: number; name?: string }[];
  next_step_to_hunt: NextStep | null;
  stall?: Stall | null;
  hunting_queries: { engine: string; query: string }[];
  affected_hosts: string[];
  affected_zones: string[];
}

interface HuntEvent { ts: string; actor: string; event: string; detail: string }

export interface HuntDetail extends Hunt {
  evidence: EvidenceRow[];
  scope_resolved: Record<string, unknown>;
  honesty_note: string;
  verdict_evidence: EvidenceRow[] | null;
  events: HuntEvent[];
}

interface ScenarioRow { scenario_id: string; name: string; severity?: string; mitre?: string }
interface Asset { hostname: string; os: string; zone: string }
interface Topology { zones: string[]; assets: Asset[] }

const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };
const SEV_COLOR: Record<string, { bg: string; fg: string }> = {
  CRITICAL: { bg: '#3a1416', fg: '#ff6b6b' }, HIGH: { bg: '#3a2600', fg: '#ffae57' },
  MEDIUM: { bg: '#2e2a00', fg: '#ffe06b' }, LOW: { bg: 'var(--panel)', fg: 'var(--muted)' },
};
const STATUS_COLOR: Record<HuntStatus, string> = {
  open: '#58a6ff', investigating: '#ffae57', confirmed: '#ff6b6b', refuted: '#3fb950', abandoned: '#9aa4b2',
};

function SeverityBadge({ severity }: { severity: string }) {
  const c = SEV_COLOR[severity] ?? SEV_COLOR.LOW;
  return <span className="px-2 py-0.5 rounded-full text-[11px] font-medium uppercase tracking-wide"
    style={{ background: c.bg, color: c.fg }}>{severity}</span>;
}

function StatusChip({ status }: { status: HuntStatus }) {
  const { t } = useTranslation();
  const color = STATUS_COLOR[status];
  return (
    <span className="px-2 py-0.5 rounded-full text-[11px] font-medium border"
      style={{ color, borderColor: color, background: 'transparent' }}>
      {t(`hunts.status.${status}`)}
    </span>
  );
}

const ctl = 'px-2.5 py-1.5 text-xs rounded-lg border transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)';
const ctlStyle = { background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' } as const;

export default function Hunts() {
  const { t } = useTranslation();
  const role = useAuthStore((s) => s.role);
  const user = useAuthStore((s) => s.user);
  const canEdit = role != null && ROLE_RANK[role] >= ROLE_RANK.analyst;
  const confirm = useConfirm();

  const [items, setItems] = useState<Hunt[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<'' | HuntStatus>('');
  const [mine, setMine] = useState(false);
  const [detail, setDetail] = useState<HuntDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const show = useToast();

  // Scope picker data.
  const [scenarios, setScenarios] = useState<ScenarioRow[]>([]);
  const [topology, setTopology] = useState<Topology | null>(null);

  // New-hunt form.
  const [hypothesis, setHypothesis] = useState('');
  const [fZone, setFZone] = useState('');
  const [fHost, setFHost] = useState('');
  const [fTactic, setFTactic] = useState('');
  const [fScenarios, setFScenarios] = useState<string[]>([]);
  const [fRange, setFRange] = useState<TimeRange>({ preset: 'all', from: null, to: null });
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    apiGet<ScenarioRow[]>('/api/scenarios').then(setScenarios).catch(() => {});
    apiGet<Topology>('/api/topology').then(setTopology).catch(() => {});
  }, []);

  const fetchHunts = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (statusFilter) params.set('status', statusFilter);
      if (mine) params.set('owner', 'me');
      const qs = params.toString();
      setItems(await apiGet<Hunt[]>('/api/hunts' + (qs ? `?${qs}` : '')));
    } catch (err) {
      show(err instanceof ApiError ? err.message : t('hunts.failedLoad'), 'error');
    } finally { setLoading(false); }
  }, [statusFilter, mine, show, t]);

  useEffect(() => { void fetchHunts(); }, [fetchHunts]);

  const loadDetail = useCallback(async (id: string) => {
    try { setDetail(await apiGet<HuntDetail>(`/api/hunts/${id}`)); }
    catch (err) { show(err instanceof ApiError ? err.message : t('hunts.failedLoad'), 'error'); }
  }, [show, t]);

  const submitHunt = async () => {
    if (hypothesis.trim() === '') { show(t('hunts.new.hypothesisRequired'), 'error'); return; }
    setSubmitting(true);
    const scope: HuntScope = {};
    if (fZone) scope.zone = fZone;
    if (fHost) scope.host = fHost;
    if (fTactic.trim()) scope.tactic = fTactic.trim();
    if (fScenarios.length) scope.scenario_ids = fScenarios;
    if (fRange.from) scope.from = fRange.from;
    if (fRange.to) scope.to = fRange.to;
    try {
      const created = await apiPost<Hunt>('/api/hunts', { hypothesis: hypothesis.trim(), scope });
      setHypothesis(''); setFZone(''); setFHost(''); setFTactic(''); setFScenarios([]);
      setFRange({ preset: 'all', from: null, to: null });
      await fetchHunts();
      await loadDetail(created.id);
    } catch (err) {
      show(err instanceof ApiError ? err.message : t('hunts.new.failed'), 'error');
    } finally { setSubmitting(false); }
  };

  const saveVerdict = async (status: HuntStatus, verdictNote: string, notes: string) => {
    if (!detail) return;
    if (TERMINAL_STATUSES.has(status) && verdictNote.trim() === '') {
      show(t('hunts.detail.verdictNoteRequired'), 'error'); return;
    }
    setBusy(true);
    try {
      await apiPatch(`/api/hunts/${detail.id}`, { status, verdict_note: verdictNote.trim(), notes });
      show(t('hunts.detail.saved'));
      await loadDetail(detail.id); await fetchHunts();
    } catch (err) { show(err instanceof ApiError ? err.message : t('hunts.detail.failedSave'), 'error'); }
    finally { setBusy(false); }
  };

  const addComment = async (text: string) => {
    if (!detail) return;
    setBusy(true);
    try {
      await apiPost(`/api/hunts/${detail.id}/comment`, { text });
      show(t('hunts.detail.commented'));
      await loadDetail(detail.id);
    } catch (err) { show(err instanceof ApiError ? err.message : t('hunts.detail.failedComment'), 'error'); }
    finally { setBusy(false); }
  };

  const deleteHunt = async () => {
    if (!detail) return;
    if (
      !(await confirm({
        title: t('common.deleteConfirmTitle'),
        message: t('hunts.detail.deleteConfirm'),
        confirmLabel: t('hunts.detail.delete'),
      }))
    )
      return;
    setBusy(true);
    try {
      await apiDelete(`/api/hunts/${detail.id}`);
      show(t('hunts.detail.deleted'));
      setDetail(null); await fetchHunts();
    } catch (err) { show(err instanceof ApiError ? err.message : t('hunts.detail.failedDelete'), 'error'); }
    finally { setBusy(false); }
  };

  return (
    <div className="w-full max-w-(--breakpoint-2xl) mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Telescope size={18} aria-hidden /> {t('hunts.title')}
        </h1>
        <p className="text-xs mt-1 max-w-2xl" style={{ color: 'var(--muted)' }}>{t('hunts.subtitle')}</p>
      </div>

      {canEdit && (
        <NewHuntForm
          hypothesis={hypothesis} setHypothesis={setHypothesis}
          zone={fZone} setZone={setFZone} host={fHost} setHost={setFHost}
          tactic={fTactic} setTactic={setFTactic}
          scenarioIds={fScenarios} setScenarioIds={setFScenarios}
          range={fRange} setRange={setFRange}
          scenarios={scenarios} topology={topology}
          submitting={submitting} onSubmit={() => void submitHunt()}
        />
      )}

      <div className="flex items-center gap-2 flex-wrap">
        <Dropdown
          value={statusFilter}
          onChange={(v) => setStatusFilter(v as '' | HuntStatus)}
          aria-label={t('hunts.list.filterStatus')}
          options={[
            { value: '', label: t('hunts.list.allStatuses') },
            ...HUNT_STATUSES.map((s) => ({ value: s, label: t(`hunts.status.${s}`) })),
          ]}
        />
        <button type="button" onClick={() => setMine((v) => !v)} aria-pressed={mine}
          className="px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors"
          style={{ background: mine ? 'var(--accent)' : 'transparent', color: mine ? '#0d1117' : 'var(--muted)', borderColor: 'var(--border)' }}>
          {t('hunts.list.mine')}
        </button>
      </div>

      {loading ? (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }} aria-label={t('hunts.loading')} />
        </div>
      ) : (
        <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
          <table className="w-full min-w-[640px] text-sm" aria-label={t('hunts.list.title')}>
            <thead style={{ background: 'var(--panel)' }}>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['status', 'hypothesis', 'owner', 'created'].map((c) => (
                  <th key={c} scope="col" className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>
                    {c === 'hypothesis' ? t('hunts.detail.hypothesis') : t(`hunts.list.${c}`)}
                  </th>
                ))}
                <th scope="col" className="px-3 py-2.5"><span className="sr-only">{t('hunts.list.view', { id: '' })}</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((h) => (
                <tr key={h.id} className="transition-colors hover:bg-[#1e242c]"
                  style={{ borderBottom: '1px solid var(--border)' }}>
                  <td className="px-3 py-2.5"><StatusChip status={h.status} /></td>
                  <td className="px-3 py-2.5 text-xs max-w-md truncate" style={{ color: 'var(--fg)' }} title={h.hypothesis}>
                    {h.hypothesis}
                  </td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--muted)' }}>{h.owner}</td>
                  <td className="px-3 py-2.5 text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                    {h.created_at ? new Date(h.created_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-3 py-2.5">
                    <button type="button" className="btn-ghost px-2 py-1 text-xs" onClick={() => void loadDetail(h.id)}
                      aria-label={t('hunts.list.view', { id: h.id })}>
                      <Eye size={12} aria-hidden />
                    </button>
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr><td colSpan={5} className="px-3 py-8 text-center text-sm" style={{ color: 'var(--muted)' }}>
                  {t('hunts.empty')}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {detail && (
        <HuntDetailPanel detail={detail} canEdit={canEdit} currentUser={user} busy={busy}
          onClose={() => setDetail(null)}
          onSave={(s, vn, n) => void saveVerdict(s, vn, n)}
          onComment={(text) => void addComment(text)}
          onDelete={() => void deleteHunt()} />
      )}
    </div>
  );
}

function NewHuntForm(props: {
  hypothesis: string; setHypothesis: (v: string) => void;
  zone: string; setZone: (v: string) => void;
  host: string; setHost: (v: string) => void;
  tactic: string; setTactic: (v: string) => void;
  scenarioIds: string[]; setScenarioIds: (v: string[]) => void;
  range: TimeRange; setRange: (r: TimeRange) => void;
  scenarios: ScenarioRow[]; topology: Topology | null;
  submitting: boolean; onSubmit: () => void;
}) {
  const { t } = useTranslation();
  const {
    hypothesis, setHypothesis, zone, setZone, host, setHost, tactic, setTactic,
    scenarioIds, setScenarioIds, range, setRange, scenarios, topology, submitting, onSubmit,
  } = props;

  const onScenarioChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setScenarioIds(Array.from(e.target.selectedOptions, (o) => o.value));
  };

  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit(); }}
      className="rounded-xl border p-4 space-y-3" style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}>
      <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{t('hunts.new.title')}</div>

      <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
        {t('hunts.new.hypothesis')}
        <textarea value={hypothesis} onChange={(e) => setHypothesis(e.target.value)} rows={2} required
          aria-label={t('hunts.new.hypothesis')} placeholder={t('hunts.new.hypothesisPlaceholder')}
          className={ctl + ' w-full resize-y'} style={ctlStyle} />
      </label>

      <div className="text-xs font-medium" style={{ color: 'var(--muted)' }}>{t('hunts.new.scope')}</div>
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
          {t('hunts.new.zone')}
          <Dropdown
            value={zone}
            onChange={setZone}
            aria-label={t('hunts.new.zone')}
            options={[
              { value: '', label: t('hunts.new.anyZone') },
              ...(topology?.zones ?? []).map((z) => ({ value: z, label: z })),
            ]}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
          {t('hunts.new.host')}
          <Dropdown
            value={host}
            onChange={setHost}
            aria-label={t('hunts.new.host')}
            options={[
              { value: '', label: t('hunts.new.anyHost') },
              ...(topology?.assets ?? []).map((a) => ({ value: a.hostname, label: a.hostname })),
            ]}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
          {t('hunts.new.tactic')}
          <input type="text" value={tactic} onChange={(e) => setTactic(e.target.value)}
            aria-label={t('hunts.new.tactic')} placeholder={t('hunts.new.tacticPlaceholder')}
            className={ctl} style={ctlStyle} />
        </label>
        <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
          {t('common.timeRange.label')}
          <TimeRangePicker value={range} onChange={setRange} label={t('common.timeRange.label')} />
        </label>
      </div>

      <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
        {t('hunts.new.scenarios')}
        <select multiple value={scenarioIds} onChange={onScenarioChange}
          aria-label={t('hunts.new.scenarios')} className={ctl + ' w-full min-h-20'} style={ctlStyle}>
          {scenarios.map((s) => <option key={s.scenario_id} value={s.scenario_id}>{s.scenario_id} · {s.name}</option>)}
        </select>
      </label>

      <div className="flex justify-end">
        <button type="submit" className="btn-primary px-3 py-1.5 text-xs rounded-lg" disabled={submitting}>
          {submitting ? t('hunts.new.submitting') : t('hunts.new.submit')}
        </button>
      </div>
    </form>
  );
}

function EvidenceCard({ row }: { row: EvidenceRow }) {
  const { t } = useTranslation();
  const pct = Math.round(row.proximity * 100);
  const ns = row.next_step_to_hunt;
  const criteria = ns ? formatCriteria(ns.matching_criteria) : '';
  const temporal = ns ? formatTemporal(ns.temporal) : null;
  return (
    <div className="rounded-lg border p-3 space-y-2" style={{ background: 'var(--bg)', borderColor: 'var(--border)' }}>
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={row.severity} />
          <span className="font-mono text-xs font-medium" style={{ color: 'var(--fg)' }}>{row.scenario_id}</span>
          <span className="text-xs" style={{ color: 'var(--muted)' }}>{row.name}</span>
        </div>
        <span className="text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
          {t('hunts.detail.matched', { matched: row.matched_count, total: row.total_steps })}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--panel)' }}>
          <div className="h-full rounded-full" style={{ width: `${pct}%`, background: 'var(--accent)' }} />
        </div>
        <span className="text-xs tabular-nums font-medium" style={{ color: 'var(--fg)' }}>{row.proximity.toFixed(4)}</span>
      </div>
      {ns && (
        <p className="text-xs" style={{ color: 'var(--muted)' }}>
          {t('dashboard.nextStep', { name: ns.name ?? '' })}
          {criteria !== '' && <> — {t('dashboard.lookFor', { criteria })}</>}
          {temporal !== null && <>; {temporal}</>}
        </p>
      )}
      {row.stall && (
        <p className="text-xs flex items-start gap-2" style={{ color: 'var(--muted)' }}>
          <AlertTriangle size={12} className="mt-0.5 shrink-0" aria-hidden />
          <span>{t('dashboard.whyStalled', { reason: formatStall(row.stall) })}</span>
        </p>
      )}
    </div>
  );
}

function HuntDetailPanel({ detail, canEdit, currentUser, busy, onClose, onSave, onComment, onDelete }: {
  detail: HuntDetail; canEdit: boolean; currentUser: string | null; busy: boolean;
  onClose: () => void;
  onSave: (status: HuntStatus, verdictNote: string, notes: string) => void;
  onComment: (text: string) => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<HuntStatus>(detail.status);
  const [verdictNote, setVerdictNote] = useState(detail.verdict_note ?? '');
  const [notes, setNotes] = useState(detail.notes ?? '');
  const [comment, setComment] = useState('');

  useEffect(() => {
    setStatus(detail.status);
    setVerdictNote(detail.verdict_note ?? '');
    setNotes(detail.notes ?? '');
  }, [detail]);

  const needsNote = TERMINAL_STATUSES.has(status);
  const isOwner = currentUser != null && currentUser === detail.owner;

  const submitComment = () => {
    if (comment.trim() === '') return;
    onComment(comment.trim());
    setComment('');
  };

  return (
    <div className="rounded-xl border p-4 space-y-4" style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
      role="region" aria-label={t('hunts.detail.title')}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <StatusChip status={detail.status} />
          <span className="text-xs" style={{ color: 'var(--muted)' }}>{detail.owner}</span>
        </div>
        <button type="button" onClick={onClose} className="btn-ghost px-2 py-1 text-xs" aria-label={t('common.closeDialog')}>✕</button>
      </div>

      <div>
        <div className="text-xs font-medium mb-1" style={{ color: 'var(--muted)' }}>{t('hunts.detail.hypothesis')}</div>
        <p className="text-sm" style={{ color: 'var(--fg)' }}>{detail.hypothesis}</p>
      </div>

      {/* Honesty banner */}
      {detail.honesty_note && (
        <div className="flex items-start gap-2 rounded-lg border px-3 py-2 text-xs"
          style={{ background: '#1a2230', borderColor: '#3b5572', color: '#9fc3ff' }} role="note">
          <Info size={14} className="mt-0.5 shrink-0" aria-hidden />
          <span>{detail.honesty_note}</span>
        </div>
      )}

      {/* Live evidence */}
      <div>
        <div className="text-xs font-medium mb-2" style={{ color: 'var(--muted)' }}>{t('hunts.detail.liveEvidence')}</div>
        {detail.evidence.length === 0 ? (
          <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('hunts.detail.noEvidence')}</p>
        ) : (
          <div className="space-y-2">
            {detail.evidence.map((row) => <EvidenceCard key={row.scenario_id} row={row} />)}
          </div>
        )}
      </div>

      {/* Verdict-time evidence snapshot — visually distinct */}
      {detail.verdict_evidence != null && (
        <div className="rounded-lg border p-3 space-y-2" style={{ borderColor: '#6b5b1a', background: '#211d10' }}>
          <div className="text-xs font-semibold" style={{ color: '#ffe06b' }}>
            {t('hunts.detail.verdictEvidenceAt', {
              at: detail.verdict_evidence_at ? new Date(detail.verdict_evidence_at).toLocaleString() : '—',
            })}
          </div>
          <p className="text-[11px]" style={{ color: 'var(--muted)' }}>{t('hunts.detail.verdictEvidenceHint')}</p>
          {detail.verdict_evidence.length === 0 ? (
            <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('hunts.detail.noEvidence')}</p>
          ) : (
            <div className="space-y-2">
              {detail.verdict_evidence.map((row) => <EvidenceCard key={`v-${row.scenario_id}`} row={row} />)}
            </div>
          )}
        </div>
      )}

      {/* Verdict / status editor */}
      {canEdit && (
        <div className="space-y-3 pt-3 border-t" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-end gap-2 flex-wrap">
            <label className="flex flex-col gap-1">
              <span className="text-xs" style={{ color: 'var(--muted)' }}>{t('hunts.detail.status')}</span>
              <Dropdown
                value={status}
                onChange={(v) => setStatus(v as HuntStatus)}
                aria-label={t('hunts.detail.status')}
                options={HUNT_STATUSES.map((s) => ({ value: s, label: t(`hunts.status.${s}`) }))}
              />
            </label>
            <button type="button" className="btn-secondary text-xs" disabled={busy}
              onClick={() => onSave(status, verdictNote, notes)}>
              {t('hunts.detail.saveVerdict')}
            </button>
          </div>
          {needsNote && (
            <textarea value={verdictNote} onChange={(e) => setVerdictNote(e.target.value)}
              aria-label={t('hunts.detail.verdictNote')} placeholder={t('hunts.detail.verdictNotePlaceholder')}
              rows={2} className={ctl + ' w-full resize-y'} style={ctlStyle} />
          )}
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: 'var(--muted)' }}>{t('hunts.detail.notes')}</span>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)}
              aria-label={t('hunts.detail.notes')} placeholder={t('hunts.detail.notesPlaceholder')}
              rows={2} className={ctl + ' w-full resize-y'} style={ctlStyle} />
          </label>

          {/* Comment */}
          <div className="flex flex-col gap-2">
            <textarea value={comment} onChange={(e) => setComment(e.target.value)}
              aria-label={t('hunts.detail.addComment')} placeholder={t('hunts.detail.addComment')}
              rows={2} className={ctl + ' w-full resize-y'} style={ctlStyle} />
            <div className="flex justify-end">
              <button type="button" className="btn-secondary text-xs" disabled={busy || comment.trim() === ''}
                onClick={submitComment}>
                {t('hunts.detail.comment')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Events timeline */}
      <div>
        <div className="text-xs font-medium mb-1" style={{ color: 'var(--muted)' }}>{t('hunts.detail.events')}</div>
        <ul className="text-xs space-y-0.5" style={{ color: 'var(--fg)' }}>
          {detail.events.map((e, i) => (
            <li key={i}>
              <span style={{ color: 'var(--muted)' }}>{e.ts ? new Date(e.ts).toLocaleString() : ''}</span> · {e.event}
              {e.actor ? <span style={{ color: 'var(--muted)' }}> ({e.actor})</span> : null}
              {e.detail ? ` — ${e.detail}` : ''}
            </li>
          ))}
          {detail.events.length === 0 && <li style={{ color: 'var(--muted)' }}>—</li>}
        </ul>
      </div>

      {/* Report + delete */}
      <div className="flex items-center gap-2 pt-3 border-t" style={{ borderColor: 'var(--border)' }}>
        <button type="button" className="btn-secondary text-xs flex items-center gap-1.5"
          onClick={() => window.open(`/api/hunts/${detail.id}/report?format=md`, '_blank', 'noopener')}>
          <FileText size={12} aria-hidden /> {t('hunts.detail.report')}
        </button>
        {canEdit && isOwner && (
          <button type="button" className="btn-ghost text-xs flex items-center gap-1.5 ml-auto" disabled={busy}
            onClick={onDelete} style={{ color: '#ff6b6b' }}>
            <Trash2 size={12} aria-hidden /> {t('hunts.detail.delete')}
          </button>
        )}
      </div>
    </div>
  );
}
