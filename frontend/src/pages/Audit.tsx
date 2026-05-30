import { useEffect, useState, useCallback } from 'react';
import { ChevronUp, ChevronDown, Minus, AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiGet, ApiError } from '../lib/api';
import SearchInput from '../components/SearchInput';
import Dropdown from '../components/Dropdown';
import Pagination from '../components/Pagination';
import { usePagination } from '../lib/usePagination';

const PAGE_SIZE = 25;

/* ──────────────────────────── Types ─────────────────────────────────────── */
export interface AuditEntry {
  id: number;
  ts: string;
  username: string;
  event: string;
  ip: string;
  detail: string;
}

/* ──────────────────────── Event tag colors ──────────────────────────────── */
const eventStyle = (event: string): { bg: string; fg: string } => {
  const e = event.toLowerCase();
  if (e.includes('login_failed') || e.includes('lockout') || e.includes('failed')) {
    return { bg: '#7a4a00', fg: '#ffd28a' };
  }
  if (e.includes('logout') || e.includes('revoke') || e.includes('delete')) {
    return { bg: '#71221c', fg: '#ffb4ab' };
  }
  if (e.includes('login') || e.includes('create') || e.includes('success')) {
    return { bg: '#162920', fg: '#3fb950' };
  }
  return { bg: '#21262d', fg: '#8b949e' };
};

function EventTag({ event }: { event: string }) {
  const { bg, fg } = eventStyle(event);
  return (
    <span
      className="px-2 py-0.5 rounded text-[11px] font-mono uppercase tracking-wide whitespace-nowrap"
      style={{ background: bg, color: fg }}
    >
      {event}
    </span>
  );
}

/* ──────────────────────────── Sorting ───────────────────────────────────── */
type SortKey = keyof AuditEntry;
type SortDir = 'asc' | 'desc';

const LIMITS = [100, 500] as const;
type Limit = typeof LIMITS[number];

/* ──────────────────────────── Audit page ────────────────────────────────── */
export default function Audit() {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState<Limit>(100);
  const [sortKey, setSortKey] = useState<SortKey>('ts');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [query, setQuery] = useState('');

  const fetchAudit = useCallback(async (lim: Limit) => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGet<AuditEntry[]>(`/api/audit?limit=${lim}`);
      setEntries(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('audit.failedLoad'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => { void fetchAudit(limit); }, [fetchAudit, limit]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir('asc'); }
  };

  const q = query.trim().toLowerCase();
  const filtered = entries.filter((e) => {
    if (!q) return true;
    return (
      e.username.toLowerCase().includes(q) ||
      e.event.toLowerCase().includes(q) ||
      e.ip.toLowerCase().includes(q) ||
      e.detail.toLowerCase().includes(q)
    );
  });

  const sorted = [...filtered].sort((a, b) => {
    const av = a[sortKey];
    const bv = b[sortKey];
    const cmp = String(av) < String(bv) ? -1 : String(av) > String(bv) ? 1 : 0;
    return sortDir === 'asc' ? cmp : -cmp;
  });

  const { page, setPage, pageCount, pageItems, total, start, end } = usePagination(sorted, PAGE_SIZE);

  function SortIcon({ col }: { col: SortKey }) {
    if (sortKey !== col) return <Minus size={12} className="opacity-30" aria-hidden />;
    return sortDir === 'asc'
      ? <ChevronUp size={12} aria-hidden />
      : <ChevronDown size={12} aria-hidden />;
  }

  function Th({ col, label }: { col: SortKey; label: string }) {
    return (
      <th
        className="px-3 py-2.5 text-left text-xs font-medium cursor-pointer select-none whitespace-nowrap transition-colors hover:text-[var(--fg)]"
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
    <div className="w-full max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
          {t('audit.title')}
        </h1>

        {/* Search + limit selector */}
        <div className="flex items-center gap-2 flex-wrap">
          {!loading && !error && (
            <SearchInput value={query} onChange={setQuery} label={t('common.search')} placeholder={t('audit.search')} />
          )}
          <label className="text-xs" style={{ color: 'var(--muted)' }}>
            {t('audit.limit')}:
          </label>
          <Dropdown
            aria-label={t('audit.limit')}
            value={String(limit)}
            onChange={(v) => setLimit(Number(v) as Limit)}
            options={LIMITS.map((l) => ({ value: String(l), label: String(l) }))}
          />
        </div>
      </div>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('audit.loading')}
          />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('audit.loading')}
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

      {!loading && !error && entries.length === 0 && (
        <div className="text-center py-16">
          <p className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('audit.empty')}
          </p>
        </div>
      )}

      {!loading && !error && entries.length > 0 && (
        <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
          <table className="w-full min-w-[720px] text-sm" aria-label={t('audit.ariaLabel')}>
            <thead style={{ background: 'var(--panel)' }}>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <Th col="ts" label={t('audit.table.timestamp')} />
                <Th col="event" label={t('audit.table.event')} />
                <Th col="username" label={t('audit.table.username')} />
                <Th col="ip" label={t('audit.table.ip')} />
                <Th col="detail" label={t('audit.table.detail')} />
              </tr>
            </thead>
            <tbody>
              {pageItems.map((entry) => (
                <tr
                  key={entry.id}
                  className="transition-colors hover:bg-[#1e242c]"
                  style={{ borderBottom: '1px solid var(--border)' }}
                >
                  <td className="px-3 py-2.5 text-xs tabular-nums whitespace-nowrap" style={{ color: 'var(--muted)' }}>
                    {entry.ts}
                  </td>
                  <td className="px-3 py-2.5">
                    <EventTag event={entry.event} />
                  </td>
                  <td className="px-3 py-2.5 text-xs font-medium" style={{ color: 'var(--fg)' }}>
                    {entry.username}
                  </td>
                  <td className="px-3 py-2.5 text-xs tabular-nums font-mono" style={{ color: 'var(--muted)' }}>
                    {entry.ip}
                  </td>
                  <td className="px-3 py-2.5 text-xs max-w-xs truncate" style={{ color: 'var(--muted)' }} title={entry.detail}>
                    {entry.detail}
                  </td>
                </tr>
              ))}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-sm" style={{ color: 'var(--muted)' }}>
                    {t('common.noMatches')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {!loading && !error && entries.length > 0 && (
        <Pagination page={page} pageCount={pageCount} total={total} start={start} end={end} onPage={setPage} />
      )}
    </div>
  );
}
