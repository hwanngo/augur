import { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Eye, Check, AlertTriangle, Loader2, Minus, Copy, X, Keyboard, Filter } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, apiPost, ApiError } from '../lib/api';
import useAuthStore, { type Role } from '../store/auth';
import TimeRangePicker, { type TimeRange } from '../components/TimeRangePicker';
import SlaChip from '../components/SlaChip';
import ExportCsvButton from '../components/ExportCsvButton';
import SavedFilters from '../components/SavedFilters';
import ShortcutsHelp from '../components/ShortcutsHelp';
import Dropdown from '../components/Dropdown';
import { toCsv, downloadCsv, type CsvColumn } from '../lib/csv';
import { type AlertSummary } from '../lib/useAlertSummary';
import { type User } from './Users';
import { formatCriteria, formatTemporal, formatStall, type Temporal, type Stall } from '../lib/nextStep';
import { useToast } from '../store/toast';

const WORKFLOW_STATUSES: WorkflowStatus[] = ['open', 'acknowledged', 'in_progress', 'resolved', 'closed'];
const TERMINAL_STATUSES = new Set<WorkflowStatus>(['resolved', 'closed']);

export type WorkflowStatus = 'open' | 'acknowledged' | 'in_progress' | 'resolved' | 'closed';
export interface AlertStep {
  step_id?: number; name?: string; host?: string | null; timestamp?: string | null;
  matching_criteria?: Record<string, unknown>; temporal?: Temporal | null;
}
export interface AlertQuery { engine: string; query: string; query_path?: string | null }
export interface Alert {
  id: string; scenario_id: string; scenario_name: string; severity: string; affected_hosts: string[];
  proximity: number; band: string; state: 'open' | 'acknowledged' | 'resolved'; first_seen: string;
  last_seen: string; count: number; notified_band: string; created_at: string;
  status: WorkflowStatus; assignee: string; resolution_note: string; assigned_at: string; resolved_at: string;
  detection: { matched_steps: AlertStep[]; missing_steps: AlertStep[]; hunting_queries: AlertQuery[]; affected_zones: string[]; stall?: Stall };
}
interface AlertEvent { ts: string; actor: string; event: string; detail: string }
type AlertDetail = Alert & { events: AlertEvent[] };
type StatusFilter = 'all' | WorkflowStatus;

/** Serialisable saved-filter snapshot for the Alerts page. */
export interface AlertsFilter {
  statusFilter: StatusFilter;
  myQueue: boolean;
  severity: string;
  range: TimeRange;
}

/** Local-clock date stamp (YYYY-MM-DD) for export filenames. */
function dateStamp(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

const ALERT_CSV_COLUMNS: CsvColumn<Alert>[] = [
  { header: 'id', value: (a) => a.id },
  { header: 'scenario_id', value: (a) => a.scenario_id },
  { header: 'scenario_name', value: (a) => a.scenario_name },
  { header: 'severity', value: (a) => a.severity },
  { header: 'band', value: (a) => a.band },
  { header: 'proximity', value: (a) => a.proximity },
  { header: 'status', value: (a) => a.status },
  { header: 'assignee', value: (a) => a.assignee },
  { header: 'affected_hosts', value: (a) => a.affected_hosts.join('; ') },
  { header: 'first_seen', value: (a) => a.first_seen },
  { header: 'last_seen', value: (a) => a.last_seen },
  { header: 'count', value: (a) => a.count },
  { header: 'resolved_at', value: (a) => a.resolved_at },
];

const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };
const SEV_COLOR: Record<string, { bg: string; fg: string }> = {
  CRITICAL: { bg: '#3a1416', fg: '#ff6b6b' }, HIGH: { bg: '#3a2600', fg: '#ffae57' },
  MEDIUM: { bg: '#2e2a00', fg: '#ffe06b' }, LOW: { bg: 'var(--panel)', fg: 'var(--muted)' },
};
const BAND_COLOR: Record<string, string> = { CONFIRMED: '#ff6b6b', HIGH: '#ffae57', WATCH: '#9aa4b2' };

function SeverityBadge({ severity }: { severity: string }) {
  const c = SEV_COLOR[severity] ?? SEV_COLOR.LOW;
  return <span className="px-2 py-0.5 rounded-full text-[11px] font-medium uppercase tracking-wide"
    style={{ background: c.bg, color: c.fg }}>{severity}</span>;
}

function CopyButton({ text }: { text: string }) {
  const { t } = useTranslation();
  const [done, setDone] = useState(false);
  return (
    <button type="button" className="btn-ghost px-2 py-1 text-xs"
      onClick={() => { void navigator.clipboard?.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500); }}
      aria-label={t('alerts.copy')}>
      <Copy size={12} aria-hidden /> {done ? t('alerts.copied') : t('alerts.copy')}
    </button>
  );
}

export default function AlertsPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const role = useAuthStore((s) => s.role);
  const user = useAuthStore((s) => s.user);
  const canAck = role != null && ROLE_RANK[role] >= ROLE_RANK.analyst;
  const isAdmin = role === 'admin';
  const [items, setItems] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [myQueue, setMyQueue] = useState(false);
  const [severity, setSeverity] = useState<string>('');
  const [range, setRange] = useState<TimeRange>({ preset: 'all', from: null, to: null });
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const show = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const dedupKeyParam = searchParams.get('dedup_key')?.trim() || '';

  // --- Bulk selection (Task 3.1/3.2) ---
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [resolving, setResolving] = useState(false);
  const [bulkNote, setBulkNote] = useState('');
  const selectAllRef = useRef<HTMLInputElement>(null);

  // --- Keyboard shortcuts (Task 4.1/4.2) ---
  const [activeIndex, setActiveIndex] = useState(0);
  const [helpOpen, setHelpOpen] = useState(false);
  const helpTriggerRef = useRef<HTMLButtonElement>(null);

  const applySavedFilter = useCallback((f: AlertsFilter) => {
    setStatusFilter(f.statusFilter);
    setMyQueue(f.myQueue);
    setSeverity(f.severity);
    setRange(f.range);
  }, []);

  const clearDeepLink = useCallback(() => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete('dedup_key');
      return next;
    });
  }, [setSearchParams]);

  const fetchSummary = useCallback(async () => {
    try { setSummary(await apiGet<AlertSummary>('/api/alerts/summary')); }
    catch { /* viewer 403 / transient — cards simply don't render */ }
  }, []);
  useEffect(() => { void fetchSummary(); }, [fetchSummary]);

  const fetchAlerts = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (statusFilter !== 'all') params.set('status', statusFilter);
      if (myQueue) params.set('assignee', 'me');
      if (severity) params.set('severity', severity);
      if (range.from) params.set('seen_from', range.from);
      if (range.to) params.set('seen_to', range.to);
      if (dedupKeyParam) params.set('dedup_key', dedupKeyParam);
      const qs = params.toString();
      setItems(await apiGet<Alert[]>('/api/alerts' + (qs ? `?${qs}` : '')));
    } catch (err) {
      show(err instanceof ApiError ? err.message : t('alerts.toasts.failedLoad'), 'error');
    } finally { setLoading(false); }
  }, [statusFilter, myQueue, severity, range.from, range.to, dedupKeyParam, show, t]);

  useEffect(() => { void fetchAlerts(); }, [fetchAlerts]);
  useEffect(() => {
    const id = setInterval(() => void fetchAlerts(), 30000);
    return () => clearInterval(id);
  }, [fetchAlerts]);

  const loadDetail = useCallback(async (id: string) => {
    try { setDetail(await apiGet<AlertDetail>(`/api/alerts/${id}`)); }
    catch (err) { show(err instanceof ApiError ? err.message : t('alerts.toasts.failedLoad'), 'error'); }
  }, [show, t]);
  const openDetail = (a: Alert) => void loadDetail(a.id);

  const ack = async (a: AlertDetail) => {
    setBusy(true);
    try {
      await apiPost(`/api/alerts/${a.id}/ack`);
      show(t('alerts.toasts.acknowledged', { id: a.scenario_id }));
      setDetail(null); await fetchAlerts();
    } catch (err) { show(err instanceof ApiError ? err.message : t('alerts.toasts.failedAck'), 'error'); }
    finally { setBusy(false); }
  };

  const assign = async (a: AlertDetail, assignee: string) => {
    setBusy(true);
    try {
      await apiPost(`/api/alerts/${a.id}/assign`, { assignee });
      show(assignee === user
        ? t('alerts.toasts.selfAssigned', { id: a.scenario_id })
        : t('alerts.toasts.assigned', { id: a.scenario_id, assignee }));
      await loadDetail(a.id); await fetchAlerts();
    } catch (err) { show(err instanceof ApiError ? err.message : t('alerts.toasts.failedAssign'), 'error'); }
    finally { setBusy(false); }
  };

  const setStatus = async (a: AlertDetail, status: WorkflowStatus, note: string) => {
    setBusy(true);
    try {
      await apiPost(`/api/alerts/${a.id}/status`, { status, note });
      show(t('alerts.toasts.statusChanged', { id: a.scenario_id, status: t(`alerts.status.${status}`) }));
      await loadDetail(a.id); await fetchAlerts();
    } catch (err) { show(err instanceof ApiError ? err.message : t('alerts.toasts.failedStatus'), 'error'); }
    finally { setBusy(false); }
  };

  const addComment = async (a: AlertDetail, text: string) => {
    setBusy(true);
    try {
      await apiPost(`/api/alerts/${a.id}/comment`, { text });
      show(t('alerts.toasts.commented'));
      await loadDetail(a.id); await fetchAlerts();
    } catch (err) { show(err instanceof ApiError ? err.message : t('alerts.toasts.failedComment'), 'error'); }
    finally { setBusy(false); }
  };

  // FP feedback loop: ask the backend for a pre-filled allowlist draft for this alert, then hand it to
  // the /tuning create form (via router state). Nothing is saved until the analyst reviews and submits.
  const proposeAllowlist = async (a: AlertDetail) => {
    setBusy(true);
    try {
      const res = await apiPost<{ draft: Record<string, unknown>; baseline_hint: unknown }>(`/api/tuning/propose_from_alert/${a.id}`);
      navigate('/tuning', { state: { draft: res.draft, baselineHint: res.baseline_hint } });
    } catch (err) { show(err instanceof ApiError ? err.message : t('alerts.toasts.failedPropose'), 'error'); }
    finally { setBusy(false); }
  };

  const handleExport = useCallback(() => {
    downloadCsv(`augur-alerts-${dateStamp()}.csv`, toCsv(items, ALERT_CSV_COLUMNS));
  }, [items]);

  // --- Selection: clear on filter / list change (stale ids) ---
  useEffect(() => {
    setSelected(new Set());
    setResolving(false);
    setBulkNote('');
  }, [statusFilter, myQueue, severity, range.from, range.to, dedupKeyParam]);

  // --- Active-row cursor: clamp + reset on filter change ---
  useEffect(() => { setActiveIndex(0); }, [statusFilter, myQueue, severity, range.from, range.to, dedupKeyParam]);
  useEffect(() => {
    setActiveIndex((i) => (items.length === 0 ? 0 : Math.min(i, items.length - 1)));
  }, [items.length]);

  // --- Header select-all indeterminate state ---
  useEffect(() => {
    const el = selectAllRef.current;
    if (!el) return;
    el.indeterminate = selected.size > 0 && selected.size < items.length;
  }, [selected, items.length]);

  const toggleRow = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);
  const toggleAll = useCallback(() => {
    setSelected((prev) => (prev.size === items.length ? new Set() : new Set(items.map((a) => a.id))));
  }, [items]);
  const clearSelection = useCallback(() => {
    setSelected(new Set());
    setResolving(false);
    setBulkNote('');
  }, []);

  /** Run `op` over every id concurrently; never throws; counts ok/fail. */
  const runBulk = useCallback(async (ids: string[], op: (id: string) => Promise<unknown>) => {
    setBusy(true);
    try {
      const results = await Promise.allSettled(ids.map(op));
      const ok = results.filter((r) => r.status === 'fulfilled').length;
      const fail = results.length - ok;
      await fetchAlerts();
      await fetchSummary();
      if (fail === 0) show(t('alerts.bulk.done', { count: ok }), 'success');
      else if (ok === 0) show(t('alerts.bulk.failed'), 'error');
      else show(t('alerts.bulk.partial', { ok, fail }), 'error');
      clearSelection();
    } finally { setBusy(false); }
  }, [fetchAlerts, fetchSummary, show, t, clearSelection]);

  const bulkIds = useMemo(() => items.filter((a) => selected.has(a.id)).map((a) => a.id), [items, selected]);
  const bulkAck = useCallback(() => void runBulk(bulkIds, (id) => apiPost(`/api/alerts/${id}/ack`)), [runBulk, bulkIds]);
  const bulkAssign = useCallback(
    () => void runBulk(bulkIds, (id) => apiPost(`/api/alerts/${id}/assign`, { assignee: user ?? '' })),
    [runBulk, bulkIds, user],
  );
  const bulkResolve = useCallback(() => {
    if (!resolving) { setResolving(true); return; }
    const note = bulkNote.trim();
    if (note === '') { show(t('alerts.detail.resolutionNoteRequired'), 'error'); return; }
    void runBulk(bulkIds, (id) => apiPost(`/api/alerts/${id}/status`, { status: 'resolved', note }));
  }, [resolving, bulkNote, show, t, runBulk, bulkIds]);

  // --- Keyboard shortcuts on the Alerts list (Task 4.2) ---
  const ackById = useCallback(async (id: string, scenarioId: string) => {
    setBusy(true);
    try {
      await apiPost(`/api/alerts/${id}/ack`);
      show(t('alerts.toasts.acknowledged', { id: scenarioId }));
      await fetchAlerts();
    } catch (err) { show(err instanceof ApiError ? err.message : t('alerts.toasts.failedAck'), 'error'); }
    finally { setBusy(false); }
  }, [show, t, fetchAlerts]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const tag = el?.tagName;
      // Never hijack typing or browser/OS chords.
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el?.isContentEditable) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      switch (e.key) {
        case 'j':
          if (items.length === 0) return;
          e.preventDefault();
          setActiveIndex((i) => Math.min(i + 1, items.length - 1));
          break;
        case 'k':
          if (items.length === 0) return;
          e.preventDefault();
          setActiveIndex((i) => Math.max(i - 1, 0));
          break;
        case 'a': {
          if (!canAck) return;
          const a = items[activeIndex];
          if (a) { e.preventDefault(); void ackById(a.id, a.scenario_id); }
          break;
        }
        case 'r': {
          const a = items[activeIndex];
          if (a) { e.preventDefault(); void loadDetail(a.id); }
          break;
        }
        case '/':
          e.preventDefault();
          document.getElementById('alerts-severity-filter')?.focus();
          break;
        case '?':
          e.preventDefault();
          setHelpOpen((v) => !v);
          break;
        default:
          break;
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [items, activeIndex, canAck, ackById, loadDetail]);

  // Scroll the active row into view (jsdom has no scrollIntoView — guarded).
  useEffect(() => {
    const a = items[activeIndex];
    if (!a) return;
    const row = document.querySelector<HTMLElement>(`tr[data-alert-id="${a.id}"]`);
    row?.scrollIntoView?.({ block: 'nearest' });
  }, [activeIndex, items]);

  const FILTERS: { value: StatusFilter; label: string }[] = [
    { value: 'all', label: t('alerts.filters.all') },
    { value: 'open', label: t('alerts.filters.open') },
    { value: 'acknowledged', label: t('alerts.filters.acknowledged') },
    { value: 'in_progress', label: t('alerts.filters.inProgress') },
    { value: 'resolved', label: t('alerts.filters.resolved') },
    { value: 'closed', label: t('alerts.filters.closed') },
  ];
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="w-full max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div>
        <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{t('alerts.title')}</h1>
        <p className="text-xs mt-1 max-w-2xl" style={{ color: 'var(--muted)' }}>{t('alerts.subtitle')}</p>
      </div>

      {summary && <SummaryCards summary={summary} onSelect={(s) => setStatusFilter(s)} />}

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-1 flex-wrap" role="tablist" aria-label={t('alerts.table.state')}>
          {FILTERS.map((f) => (
            <button key={f.value} type="button" role="tab" aria-selected={statusFilter === f.value}
              onClick={() => setStatusFilter(f.value)} className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
              style={{ background: statusFilter === f.value ? 'var(--accent)' : 'transparent', color: statusFilter === f.value ? '#0d1117' : 'var(--muted)' }}>
              {f.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button type="button" onClick={() => setMyQueue((v) => !v)} aria-pressed={myQueue}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors"
            style={{ background: myQueue ? 'var(--accent)' : 'transparent', color: myQueue ? '#0d1117' : 'var(--muted)', borderColor: 'var(--border)' }}>
            {t('alerts.filters.myQueue')}
          </button>
          <TimeRangePicker value={range} onChange={setRange} label={t('common.timeRange.label')} />
          <Dropdown
            id="alerts-severity-filter"
            value={severity}
            onChange={setSeverity}
            aria-label={t('alerts.table.severity')}
            options={[
              { value: '', label: t('alerts.filters.allSeverities') },
              ...SEVS.map((s) => ({ value: s, label: s })),
            ]}
          />
          <SavedFilters<AlertsFilter>
            scope="alerts"
            user={user}
            current={{ statusFilter, myQueue, severity, range }}
            onApply={applySavedFilter}
            show={show}
          />
          <ExportCsvButton onExport={handleExport} disabled={items.length === 0} label={t('common.exportCsv')} />
          <button ref={helpTriggerRef} type="button" onClick={() => setHelpOpen(true)}
            className="btn-ghost text-xs flex items-center gap-1.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
            aria-label={t('shortcuts.hint')}>
            <Keyboard size={12} aria-hidden />
            {t('shortcuts.hint')}
          </button>
        </div>
      </div>

      {dedupKeyParam && (
        <div
          className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-xs"
          style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--fg)' }}
          role="status"
        >
          <span>{t('alerts.deepLink.banner')}</span>
          <button
            type="button"
            onClick={clearDeepLink}
            className="btn-ghost px-2 py-1 flex items-center gap-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
          >
            <X size={12} aria-hidden />
            {t('alerts.deepLink.clear')}
          </button>
        </div>
      )}

      {canAck && selected.size > 0 && (
        <div role="region" aria-label={t('alerts.bulk.label')}
          className="flex items-center gap-3 flex-wrap rounded-lg border px-3 py-2 sticky top-2 z-10"
          style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}>
          <span className="text-xs font-medium" aria-live="polite" style={{ color: 'var(--fg)' }}>
            {t('alerts.bulk.count', { count: selected.size })}
          </span>
          <button type="button" className="btn-secondary text-xs" disabled={busy} onClick={bulkAck}>
            {t('alerts.bulk.acknowledge')}
          </button>
          <button type="button" className="btn-secondary text-xs" disabled={busy} onClick={bulkAssign}>
            {t('alerts.bulk.assignToMe')}
          </button>
          {resolving && (
            // Focus-on-open: the bulk-resolve note field appears on demand; focusing it is the expected edit-mode UX.
            // eslint-disable-next-line jsx-a11y/no-autofocus
            <input type="text" value={bulkNote} autoFocus onChange={(e) => setBulkNote(e.target.value)}
              aria-label={t('alerts.bulk.notePlaceholder')} placeholder={t('alerts.bulk.notePlaceholder')}
              className="px-2.5 py-1.5 text-xs rounded-lg border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
              style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }} />
          )}
          <button type="button" className="btn-secondary text-xs" disabled={busy} onClick={bulkResolve}>
            {t('alerts.bulk.resolve')}
          </button>
          <button type="button" className="btn-ghost text-xs ml-auto" onClick={clearSelection}>
            {t('alerts.bulk.clear')}
          </button>
        </div>
      )}

      {loading ? (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }} aria-label={t('alerts.loading')} />
        </div>
      ) : (
        <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
          <table className="w-full min-w-[720px] text-sm" aria-label={t('alerts.title')}>
            <thead style={{ background: 'var(--panel)' }}>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {canAck && (
                  <th scope="col" className="px-3 py-2.5">
                    <input ref={selectAllRef} type="checkbox"
                      checked={items.length > 0 && selected.size === items.length}
                      onChange={toggleAll} aria-label={t('alerts.bulk.selectAll')}
                      className="accent-[var(--accent)] cursor-pointer" />
                  </th>
                )}
                {['severity', 'scenario', 'band', 'proximity', 'hosts', 'state', 'assignee', 'age', 'lastSeen', 'count'].map((c) => (
                  <th key={c} scope="col" className="px-3 py-2.5 text-left text-xs font-medium" style={{ color: 'var(--muted)' }}>{t(`alerts.table.${c}`)}</th>
                ))}
                <th scope="col" className="px-3 py-2.5"><span className="sr-only">{t('alerts.table.actions')}</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((a, idx) => (
                <tr key={a.id} data-alert-id={a.id}
                  data-active={idx === activeIndex ? 'true' : 'false'}
                  aria-selected={idx === activeIndex}
                  className="transition-colors hover:bg-[#1e242c] data-[active=true]:bg-[#1e242c]"
                  style={{ borderBottom: '1px solid var(--border)',
                    boxShadow: idx === activeIndex ? 'inset 2px 0 0 var(--accent)' : undefined }}>
                  {canAck && (
                    <td className="px-3 py-2.5">
                      <input type="checkbox" checked={selected.has(a.id)}
                        onChange={() => toggleRow(a.id)}
                        aria-label={t('alerts.bulk.selectRow', { id: a.scenario_id })}
                        className="accent-[var(--accent)] cursor-pointer" />
                    </td>
                  )}
                  <td className="px-3 py-2.5"><SeverityBadge severity={a.severity} /></td>
                  <td className="px-3 py-2.5">
                    <span className="font-mono text-xs font-medium" style={{ color: 'var(--fg)' }}>{a.scenario_id}</span>
                    <span className="block text-[11px]" style={{ color: 'var(--muted)' }}>{a.scenario_name}</span>
                  </td>
                  <td className="px-3 py-2.5 text-xs font-medium" style={{ color: BAND_COLOR[a.band] ?? 'var(--muted)' }}>{a.band}</td>
                  <td className="px-3 py-2.5 tabular-nums text-xs" style={{ color: 'var(--fg)' }}>{Math.round(a.proximity * 100)}%</td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: 'var(--muted)' }}>{a.affected_hosts.join(', ') || '—'}</td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: a.status === 'open' ? 'var(--accent)' : 'var(--muted)' }}>{t(`alerts.status.${a.status}`)}</td>
                  <td className="px-3 py-2.5 text-xs" style={{ color: a.assignee ? 'var(--fg)' : 'var(--muted)' }}>{a.assignee || '—'}</td>
                  <td className="px-3 py-2.5"><SlaChip createdAt={a.created_at} resolvedAt={a.resolved_at || null} status={a.status} /></td>
                  <td className="px-3 py-2.5 text-xs tabular-nums" style={{ color: 'var(--muted)' }}>{a.last_seen ? new Date(a.last_seen).toLocaleString() : '—'}</td>
                  <td className="px-3 py-2.5 tabular-nums text-xs" style={{ color: 'var(--muted)' }}>{a.count}</td>
                  <td className="px-3 py-2.5">
                    <button type="button" className="btn-ghost px-2 py-1 text-xs" onClick={() => void openDetail(a)}
                      aria-label={t('alerts.actions.view', { id: a.scenario_id })} title={t('alerts.detailTitle', { id: a.scenario_id })}>
                      <Eye size={12} aria-hidden />
                    </button>
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr><td colSpan={canAck ? 12 : 11} className="px-3 py-8 text-center text-sm" style={{ color: 'var(--muted)' }}>
                  {dedupKeyParam ? t('alerts.deepLink.noCase') : t('alerts.empty')}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {detail && <AlertDrawer detail={detail} canAck={canAck} isAdmin={isAdmin} currentUser={user} busy={busy}
        onClose={() => setDetail(null)} onAck={() => void ack(detail)}
        onAssign={(who) => void assign(detail, who)}
        onSetStatus={(s, note) => void setStatus(detail, s, note)}
        onComment={(text) => void addComment(detail, text)}
        onPropose={() => void proposeAllowlist(detail)}
        onNoteRequired={() => show(t('alerts.detail.resolutionNoteRequired'), 'error')} />}
      <ShortcutsHelp open={helpOpen} onClose={() => setHelpOpen(false)} returnFocusRef={helpTriggerRef} />
    </div>
  );
}

function SummaryCards({ summary, onSelect }:
  { summary: AlertSummary; onSelect: (s: StatusFilter) => void }) {
  const { t } = useTranslation();
  const by = summary.by_status ?? {};
  const cards: { key: string; label: string; count: number; status: StatusFilter | null }[] = [
    { key: 'open', label: t('alerts.summary.open'), count: by.open ?? summary.open_count ?? 0, status: 'open' },
    { key: 'acknowledged', label: t('alerts.summary.acknowledged'), count: by.acknowledged ?? 0, status: 'acknowledged' },
    { key: 'in_progress', label: t('alerts.summary.inProgress'), count: by.in_progress ?? summary.in_progress_count ?? 0, status: 'in_progress' },
    { key: 'resolved', label: t('alerts.summary.resolved'), count: by.resolved ?? summary.resolved_count ?? 0, status: 'resolved' },
    { key: 'closed', label: t('alerts.summary.closed'), count: by.closed ?? summary.closed_count ?? 0, status: 'closed' },
    { key: 'unassigned', label: t('alerts.summary.unassigned'), count: summary.unassigned_count ?? 0, status: null },
  ];
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
      {cards.map((c) => (
        <button key={c.key} type="button"
          onClick={() => { if (c.status) onSelect(c.status); }}
          className="rounded-xl border p-3 text-left transition-colors hover:bg-[#1e242c] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
          style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}>
          <div className="text-2xl font-semibold tabular-nums" style={{ color: 'var(--fg)' }}>{c.count}</div>
          <div className="text-xs" style={{ color: 'var(--muted)' }}>{c.label}</div>
        </button>
      ))}
    </div>
  );
}

function AlertDrawer({ detail, canAck, isAdmin, currentUser, busy, onClose, onAck, onAssign, onSetStatus, onComment, onPropose, onNoteRequired }:
  { detail: AlertDetail; canAck: boolean; isAdmin: boolean; currentUser: string | null; busy: boolean;
    onClose: () => void; onAck: () => void;
    onAssign: (assignee: string) => void;
    onSetStatus: (status: WorkflowStatus, note: string) => void;
    onComment: (text: string) => void;
    onPropose: () => void;
    onNoteRequired: () => void }) {
  const { t } = useTranslation();
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', h); return () => document.removeEventListener('keydown', h);
  }, [onClose]);
  const root = document.getElementById('modal-root') ?? document.body;
  const d = detail.detection;
  const content = (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden />
      <div className="relative z-10 w-full max-w-3xl rounded-xl border shadow-xl max-h-[85vh] overflow-auto"
        style={{ background: 'var(--panel)', borderColor: 'var(--border)' }} role="dialog" aria-modal aria-labelledby="alert-title">
        <div className="flex items-center justify-between p-4 border-b sticky top-0" style={{ borderColor: 'var(--border)', background: 'var(--panel)' }}>
          <h2 id="alert-title" className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>{t('alerts.detailTitle', { id: detail.scenario_id })}</h2>
          <button type="button" onClick={onClose} className="btn-ghost p-1" aria-label="Close"><Minus size={14} aria-hidden /></button>
        </div>
        <div className="p-4 space-y-4">
          <div className="flex flex-wrap items-center gap-4 text-xs" style={{ color: 'var(--muted)' }}>
            <SeverityBadge severity={detail.severity} />
            <span>{t('alerts.table.band')}: <span style={{ color: BAND_COLOR[detail.band] ?? 'var(--fg)' }}>{detail.band}</span></span>
            <span>{t('alerts.table.proximity')}: <span className="tabular-nums" style={{ color: 'var(--fg)' }}>{Math.round(detail.proximity * 100)}%</span></span>
            <span>{t('alerts.detail.count')}: <span style={{ color: 'var(--fg)' }}>{detail.count}</span></span>
            <span>{t('alerts.detail.firstSeen')}: <span style={{ color: 'var(--fg)' }}>{new Date(detail.first_seen).toLocaleString()}</span></span>
          </div>
          <Section title={t('alerts.detail.hosts')}>
            <p className="text-xs" style={{ color: 'var(--fg)' }}>{detail.affected_hosts.join(', ') || '—'}
              {d.affected_zones?.length ? <span style={{ color: 'var(--muted)' }}> · {d.affected_zones.join(', ')}</span> : null}</p>
          </Section>
          <Section title={t('alerts.detail.matched')}>
            <ul className="text-xs space-y-0.5" style={{ color: 'var(--fg)' }}>
              {d.matched_steps.map((s, i) => <li key={i}>{s.step_id}. {s.name} {s.host ? <span style={{ color: 'var(--muted)' }}>@ {s.host}</span> : null}</li>)}
              {d.matched_steps.length === 0 && <li style={{ color: 'var(--muted)' }}>—</li>}
            </ul>
          </Section>
          {d.missing_steps.length > 0 && (
            <Section title={t('alerts.detail.missing')}>
              <ul className="text-xs space-y-1" style={{ color: 'var(--muted)' }}>
                {d.missing_steps.map((s, i) => {
                  const criteria = formatCriteria(s.matching_criteria);
                  const temporal = formatTemporal(s.temporal);
                  const hasGuidance = criteria !== '' || temporal !== null;
                  return (
                    <li key={i}>
                      {s.step_id}. {s.name}
                      {hasGuidance && (
                        <span className="block mt-0.5">
                          {t('dashboard.nextStep', { name: s.name })}
                          {criteria !== '' && <> — {t('dashboard.lookFor', { criteria })}</>}
                          {temporal !== null && <>; {temporal}</>}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </Section>
          )}
          {d.stall && (
            <p className="text-xs flex items-start gap-2" style={{ color: 'var(--muted)' }}>
              <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" aria-hidden />
              <span>{t('dashboard.whyStalled', { reason: formatStall(d.stall) })}</span>
            </p>
          )}
          <Section title={t('alerts.detail.queries')}>
            {d.hunting_queries.length ? d.hunting_queries.map((q, i) => (
              <div key={i} className="mb-2">
                <div className="flex items-center justify-between"><span className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{q.engine}</span><CopyButton text={q.query} /></div>
                <pre className="text-xs rounded-lg border p-2 overflow-auto font-mono" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}>{q.query}</pre>
              </div>
            )) : <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('alerts.detail.noQueries')}</p>}
          </Section>
          <Section title={t('alerts.detail.history')}>
            <ul className="text-xs space-y-0.5" style={{ color: 'var(--fg)' }}>
              {detail.events.map((e, i) => <li key={i}><span style={{ color: 'var(--muted)' }}>{e.ts ? new Date(e.ts).toLocaleString() : ''}</span> · {e.event} {e.actor ? <span style={{ color: 'var(--muted)' }}>({e.actor})</span> : null} {e.detail ? `— ${e.detail}` : ''}</li>)}
            </ul>
          </Section>
          {canAck && (
            <div className="flex items-center justify-between gap-2 pt-2 border-t flex-wrap" style={{ borderColor: 'var(--border)' }}>
              <span className="text-xs" style={{ color: 'var(--muted)' }}>{t('alerts.detail.falsePositiveHint')}</span>
              <button type="button" onClick={onPropose} disabled={busy}
                className="btn-ghost text-xs flex items-center gap-1.5" style={{ color: 'var(--accent)' }}>
                <Filter size={13} aria-hidden /> {t('alerts.proposeAllowlist')}
              </button>
            </div>
          )}
          {canAck && (
            <TriageActions detail={detail} isAdmin={isAdmin} currentUser={currentUser} busy={busy}
              onAssign={onAssign} onSetStatus={onSetStatus} onComment={onComment} onNoteRequired={onNoteRequired} />
          )}
          {canAck && detail.state === 'open' && (
            <div className="flex justify-end pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
              <button type="button" className="btn-primary" disabled={busy} onClick={onAck}>
                {busy ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <Check size={14} aria-hidden />}{t('alerts.ack')}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
  return createPortal(content, root);
}

function TriageActions({ detail, isAdmin, currentUser, busy, onAssign, onSetStatus, onComment, onNoteRequired }:
  { detail: AlertDetail; isAdmin: boolean; currentUser: string | null; busy: boolean;
    onAssign: (assignee: string) => void;
    onSetStatus: (status: WorkflowStatus, note: string) => void;
    onComment: (text: string) => void;
    onNoteRequired: () => void }) {
  const { t } = useTranslation();
  const [users, setUsers] = useState<User[]>([]);
  const [pickAssignee, setPickAssignee] = useState('');
  const [status, setStatus] = useState<WorkflowStatus>(detail.status);
  const [note, setNote] = useState(detail.resolution_note ?? '');
  const [comment, setComment] = useState('');

  useEffect(() => {
    if (!isAdmin) return;
    void apiGet<User[]>('/api/users')
      .then((list) => setUsers(list.filter((u) => !u.disabled)))
      .catch(() => { /* admin-only fetch failure: select simply has no options */ });
  }, [isAdmin]);

  const needsNote = TERMINAL_STATUSES.has(status);
  const submitStatus = () => {
    if (needsNote && note.trim() === '') { onNoteRequired(); return; }
    onSetStatus(status, note.trim());
  };
  const submitComment = () => {
    if (comment.trim() === '') return;
    onComment(comment.trim());
    setComment('');
  };

  const ctl = 'px-2.5 py-1.5 text-xs rounded-lg border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]';
  const ctlStyle = { background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' } as const;

  return (
    <div className="space-y-4 pt-3 border-t" style={{ borderColor: 'var(--border)' }}>
      {/* Assign */}
      <div className="flex items-end gap-2 flex-wrap">
        <button type="button" className="btn-secondary text-xs" disabled={busy}
          onClick={() => onAssign(currentUser ?? '')}>
          {t('alerts.actions.assignToMe')}
        </button>
        {isAdmin && (
          <div className="flex items-end gap-2">
            <label className="flex flex-col gap-1">
              <span className="text-xs" style={{ color: 'var(--muted)' }}>{t('alerts.detail.assignee')}</span>
              <Dropdown
                value={pickAssignee}
                onChange={setPickAssignee}
                aria-label={t('alerts.actions.assign')}
                placeholder={t('alerts.detail.unassigned')}
                options={users.map((u) => ({ value: u.username, label: u.username }))}
                menuPortal
              />
            </label>
            <button type="button" className="btn-secondary text-xs" disabled={busy}
              onClick={() => onAssign(pickAssignee)}>
              {t('alerts.actions.assign')}
            </button>
          </div>
        )}
      </div>

      {/* Set status */}
      <div className="flex flex-col gap-2">
        <div className="flex items-end gap-2 flex-wrap">
          <label className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: 'var(--muted)' }}>{t('alerts.detail.status')}</span>
            <Dropdown
              value={status}
              onChange={(v) => setStatus(v as WorkflowStatus)}
              aria-label={t('alerts.actions.setStatus')}
              options={WORKFLOW_STATUSES.map((s) => ({ value: s, label: t(`alerts.status.${s}`) }))}
              menuPortal
            />
          </label>
          <button type="button" className="btn-secondary text-xs" disabled={busy} onClick={submitStatus}>
            {t('alerts.actions.setStatus')}
          </button>
        </div>
        {needsNote && (
          <textarea value={note} onChange={(e) => setNote(e.target.value)}
            aria-label={t('alerts.detail.resolutionNote')} placeholder={t('alerts.detail.resolutionNote')}
            rows={2} className={ctl + ' w-full resize-y'} style={ctlStyle} />
        )}
      </div>

      {/* Comment */}
      <div className="flex flex-col gap-2">
        <textarea value={comment} onChange={(e) => setComment(e.target.value)}
          aria-label={t('alerts.detail.addComment')} placeholder={t('alerts.detail.addComment')}
          rows={2} className={ctl + ' w-full resize-y'} style={ctlStyle} />
        <div className="flex justify-end">
          <button type="button" className="btn-secondary text-xs" disabled={busy || comment.trim() === ''}
            onClick={submitComment}>
            {t('alerts.actions.comment')}
          </button>
        </div>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs font-medium mb-1" style={{ color: 'var(--muted)' }}>{title}</div>
      {children}
    </div>
  );
}
