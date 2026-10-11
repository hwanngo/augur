import { Download } from 'lucide-react';

interface Props {
  onExport: () => void;
  disabled?: boolean;
  label: string;
}

/**
 * Toolbar button that triggers a client-side CSV export of the current view.
 * Plain `<button>` (role button, never a combobox) so it can't collide with the
 * scoped-combobox page tests. Disabled when the current view has no rows.
 */
export default function ExportCsvButton({ onExport, disabled = false, label }: Props) {
  return (
    <button
      type="button"
      onClick={onExport}
      disabled={disabled}
      aria-label={label}
      className="btn-secondary text-xs flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
    >
      <Download size={12} aria-hidden />
      {label}
    </button>
  );
}
