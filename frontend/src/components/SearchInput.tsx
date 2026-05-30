import { Search, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

interface Props {
  value: string;
  onChange: (value: string) => void;
  label: string;
  placeholder?: string;
}

/** Labeled search box with a leading icon and a clear button (shown when non-empty). */
export default function SearchInput({ value, onChange, label, placeholder }: Props) {
  const { t } = useTranslation();
  return (
    <div className="relative">
      <Search
        size={14}
        className="absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none"
        style={{ color: 'var(--muted)' }}
        aria-hidden
      />
      <input
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={label}
        className="w-56 max-w-full pl-8 pr-8 py-1.5 text-xs rounded-lg border transition-colors
                   focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
        style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          aria-label={t('common.clearSearch')}
          className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 rounded transition-colors
                     hover:text-[var(--fg)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
          style={{ color: 'var(--muted)' }}
        >
          <X size={12} aria-hidden />
        </button>
      )}
    </div>
  );
}
