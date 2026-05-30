import { useEffect, useState } from 'react';
import { Save, Trash2, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  loadSavedFilters,
  saveSavedFilter,
  deleteSavedFilter,
  type SavedFilter,
} from '../lib/savedFilters';
import { useConfirm } from './useConfirm';
import Dropdown from './Dropdown';

interface Props<F> {
  scope: 'alerts' | 'dashboard';
  user: string | null;
  /** The live filter record to "Save current as…". */
  current: F;
  /** Page sets its filter state from a recalled filter. */
  onApply: (value: F) => void;
  /** Toast callback (matches the page's `useToast().show`). */
  show: (message: string, type?: 'success' | 'error') => void;
}

/**
 * Toolbar control to recall / save / delete named filter snapshots for a page.
 * Owns its own list state (seeded from localStorage, re-keyed when `user`
 * changes). The recall `Dropdown` gets a unique accessible name so the
 * scoped-combobox page tests stay unambiguous.
 */
export default function SavedFilters<F>({ scope, user, current, onApply, show }: Props<F>) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [list, setList] = useState<SavedFilter<F>[]>([]);
  const [selected, setSelected] = useState('');
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState('');

  useEffect(() => {
    setList(loadSavedFilters<F>(scope, user));
    setSelected('');
  }, [scope, user]);

  const ctl =
    'px-2.5 py-1.5 text-xs rounded-lg border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]';
  const ctlStyle = { background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' } as const;

  const handleRecall = (id: string) => {
    setSelected(id);
    const found = list.find((f) => f.id === id);
    if (found) onApply(found.value);
  };

  const confirmSave = () => {
    const trimmed = name.trim();
    if (!trimmed) return;
    const next = saveSavedFilter<F>(scope, user, trimmed, current);
    setList(next);
    const picked = next.find((f) => f.name === trimmed);
    if (picked) setSelected(picked.id);
    setSaving(false);
    setName('');
    show(t('savedFilters.saved', { name: trimmed }), 'success');
  };

  const cancelSave = () => {
    setSaving(false);
    setName('');
  };

  const selectedFilter = list.find((f) => f.id === selected);

  const handleDelete = async () => {
    if (!selected) return;
    const name = selectedFilter?.name ?? selected;
    if (
      !(await confirm({
        title: t('common.deleteConfirmTitle'),
        message: t('savedFilters.deleteConfirm', { name }),
        confirmLabel: t('common.delete'),
      }))
    )
      return;
    const next = deleteSavedFilter<F>(scope, user, selected);
    setList(next);
    setSelected('');
    show(t('savedFilters.deleted'), 'success');
  };

  return (
    <div className="flex items-center gap-2">
      <Dropdown
        value={selected}
        onChange={handleRecall}
        aria-label={t('savedFilters.recall')}
        placeholder={t('savedFilters.none')}
        options={list.map((f) => ({ value: f.id, label: f.name }))}
        disabled={list.length === 0}
      />

      {saving ? (
        <div className="flex items-center gap-1">
          <input
            type="text"
            value={name}
            // Focus-on-open: the inline rename field appears on demand; focusing it is the expected edit-mode UX.
            // eslint-disable-next-line jsx-a11y/no-autofocus
            autoFocus
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') confirmSave();
              else if (e.key === 'Escape') {
                e.stopPropagation();
                cancelSave();
              }
            }}
            aria-label={t('savedFilters.namePlaceholder')}
            placeholder={t('savedFilters.namePlaceholder')}
            className={ctl}
            style={ctlStyle}
          />
          <button type="button" className="btn-secondary text-xs" onClick={confirmSave}>
            {t('savedFilters.confirmName')}
          </button>
          <button
            type="button"
            className="btn-ghost px-1.5 py-1"
            onClick={cancelSave}
            aria-label={t('savedFilters.cancel')}
          >
            <X size={12} aria-hidden />
          </button>
        </div>
      ) : (
        <button
          type="button"
          className="btn-secondary text-xs flex items-center gap-1.5"
          onClick={() => setSaving(true)}
        >
          <Save size={12} aria-hidden />
          {t('savedFilters.save')}
        </button>
      )}

      <button
        type="button"
        className="btn-ghost px-1.5 py-1 disabled:opacity-40 disabled:cursor-not-allowed"
        onClick={handleDelete}
        disabled={!selectedFilter}
        aria-label={t('savedFilters.delete', { name: selectedFilter?.name ?? '' })}
      >
        <Trash2 size={12} aria-hidden />
      </button>
    </div>
  );
}
