import { useTranslation } from 'react-i18next';
import Dropdown from './Dropdown';

export type Preset = '24h' | '7d' | '30d' | 'custom' | 'all';
export type TimeRange = { preset: Preset; from: string | null; to: string | null };

interface Props {
  value: TimeRange;
  onChange: (r: TimeRange) => void;
  label: string; // aria-label / visible label
}

const PRESET_MS: Record<'24h' | '7d' | '30d', number> = {
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
};

const INPUT =
  'px-2.5 py-1.5 text-xs rounded-lg border transition-colors ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]';

/** Convert an absolute ISO string into the `datetime-local` input value (local wall-clock, no seconds). */
function isoToLocalInput(iso: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

/** Convert a `datetime-local` input value back into an absolute ISO string. */
function localInputToIso(local: string): string | null {
  if (!local) return null;
  const d = new Date(local);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

/**
 * Preset time-range picker. A single `Dropdown` (All / 24h / 7d / 30d / Custom) plus two
 * `datetime-local` inputs revealed for the custom preset. Relative presets are resolved to
 * absolute ISO bounds against the *client* clock (`new Date()`) at change time, so the server
 * and engine only ever see absolute timestamps.
 */
export default function TimeRangePicker({ value, onChange, label }: Props) {
  const { t } = useTranslation();

  const onPreset = (preset: Preset) => {
    if (preset === 'all') {
      onChange({ preset: 'all', from: null, to: null });
      return;
    }
    if (preset === 'custom') {
      onChange({ preset: 'custom', from: value.from, to: value.to });
      return;
    }
    const now = new Date();
    const from = new Date(now.getTime() - PRESET_MS[preset]);
    onChange({ preset, from: from.toISOString(), to: now.toISOString() });
  };

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <Dropdown
        value={value.preset}
        onChange={(v) => onPreset(v as Preset)}
        aria-label={label}
        options={[
          { value: 'all', label: t('common.timeRange.all') },
          { value: '24h', label: t('common.timeRange.last24h') },
          { value: '7d', label: t('common.timeRange.last7d') },
          { value: '30d', label: t('common.timeRange.last30d') },
          { value: 'custom', label: t('common.timeRange.custom') },
        ]}
      />

      {value.preset === 'custom' && (
        <>
          <input
            type="datetime-local"
            value={isoToLocalInput(value.from)}
            onChange={(e) =>
              onChange({ preset: 'custom', from: localInputToIso(e.target.value), to: value.to })
            }
            aria-label={t('common.timeRange.from')}
            className={INPUT}
            style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
          />
          <input
            type="datetime-local"
            value={isoToLocalInput(value.to)}
            onChange={(e) =>
              onChange({ preset: 'custom', from: value.from, to: localInputToIso(e.target.value) })
            }
            aria-label={t('common.timeRange.to')}
            className={INPUT}
            style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
          />
        </>
      )}
    </div>
  );
}
