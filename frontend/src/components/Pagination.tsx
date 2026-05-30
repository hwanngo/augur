import { ChevronLeft, ChevronRight } from 'lucide-react';
import { useTranslation } from 'react-i18next';

interface Props {
  page: number;
  pageCount: number;
  total: number;
  start: number;
  end: number;
  onPage: (page: number) => void;
}

const BTN =
  'inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ' +
  'cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]';

/** Accessible prev/next pager. Renders nothing when everything fits on one page. */
export default function Pagination({ page, pageCount, total, start, end, onPage }: Props) {
  const { t } = useTranslation();
  if (pageCount <= 1) return null;

  return (
    <nav className="flex items-center justify-between gap-3 flex-wrap pt-1" aria-label={t('common.pagination')}>
      <span className="text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
        {t('common.pageRange', { start, end, total })}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          className={BTN}
          style={{ borderColor: 'var(--border)', color: 'var(--fg)', background: 'var(--panel)' }}
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          aria-label={t('common.previous')}
        >
          <ChevronLeft size={14} aria-hidden /> {t('common.previous')}
        </button>
        <span className="text-xs tabular-nums" style={{ color: 'var(--muted)' }} aria-live="polite">
          {t('common.pageOf', { page, pageCount })}
        </span>
        <button
          type="button"
          className={BTN}
          style={{ borderColor: 'var(--border)', color: 'var(--fg)', background: 'var(--panel)' }}
          disabled={page >= pageCount}
          onClick={() => onPage(page + 1)}
          aria-label={t('common.next')}
        >
          {t('common.next')} <ChevronRight size={14} aria-hidden />
        </button>
      </div>
    </nav>
  );
}
