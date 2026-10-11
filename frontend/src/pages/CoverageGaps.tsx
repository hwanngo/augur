import { useEffect, useState } from 'react';
import { AlertTriangle, Info } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { apiGet, ApiError } from '../lib/api';
import ExportCsvButton from '../components/ExportCsvButton';
import { downloadJson, dateStamp } from '../lib/csv';

/* ──────────────────────────── Types ─────────────────────────────────────── */
interface Cell {
  covered: boolean;
  count: number;
}
interface Tactic {
  id: string;
  name: string;
}
interface Summary {
  os_families: string[];
  total_cells: number;
  covered_cells: number;
  gap_cells: number;
  coverage_pct: number;
}
interface CoverageResponse {
  tactics: Tactic[];
  os_families: string[];
  cells: Record<string, Record<string, Cell>>;
  summary: Summary;
}

/* ──────────────────────── Coverage Gap Matrix page ───────────────────────── */
export default function CoverageGaps() {
  const { t } = useTranslation();
  const [data, setData] = useState<CoverageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<CoverageResponse>('/api/coverage_gaps')
      .then((d) => {
        setData(d);
        setLoading(false);
      })
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : t('coverageGaps.failedLoad'));
        setLoading(false);
      });
  }, [t]);

  const empty = !!data && data.os_families.length === 0;

  const handleExportLayer = () => {
    apiGet<unknown>('/api/navigator_layer?type=coverage')
      .then((layer) => downloadJson(`augur-attack-coverage-${dateStamp()}.json`, layer))
      .catch(() => setError(t('coverageGaps.failedLoad')));
  };

  return (
    <div className="w-full max-w-(--breakpoint-2xl) mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
            {t('coverageGaps.title')}
          </h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>
            {t('coverageGaps.subtitle')}
          </p>
        </div>
        {!loading && !error && data && !empty && (
          <ExportCsvButton onExport={handleExportLayer} disabled={false} label={t('common.exportAttackLayer')} />
        )}
      </div>

      {loading && (
        <div className="flex items-center gap-3 py-12 justify-center">
          <div
            className="w-6 h-6 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--accent)' }}
            aria-label={t('coverageGaps.loading')}
          />
          <span className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('coverageGaps.loading')}
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

      {!loading && !error && empty && (
        <div className="text-center py-16">
          <p className="text-sm" style={{ color: 'var(--muted)' }}>
            {t('coverageGaps.empty')}
          </p>
        </div>
      )}

      {!loading && !error && data && !empty && (
        <>
          <p className="text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
            {t('coverageGaps.summary', {
              covered: data.summary.covered_cells,
              total: data.summary.total_cells,
              pct: Math.round(data.summary.coverage_pct * 100),
              gaps: data.summary.gap_cells,
            })}
          </p>

          <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
            <table className="w-full text-sm" aria-label={t('coverageGaps.ariaLabel')}>
              <thead style={{ background: 'var(--panel)' }}>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th
                    className="px-3 py-2.5 text-left text-xs font-medium"
                    style={{ color: 'var(--muted)' }}
                  >
                    {t('coverageGaps.title')}
                  </th>
                  {data.os_families.map((os) => (
                    <th
                      key={os}
                      className="px-3 py-2.5 text-center text-xs font-medium uppercase"
                      style={{ color: 'var(--muted)' }}
                    >
                      {os}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.tactics.map((tac) => (
                  <tr key={tac.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td className="px-3 py-2.5 text-xs font-medium" style={{ color: 'var(--fg)' }}>
                      {tac.name}
                    </td>
                    {data.os_families.map((os) => {
                      const cell = data.cells[tac.id]?.[os] ?? { covered: false, count: 0 };
                      return (
                        <td key={os} className="px-3 py-2.5 text-center">
                          {cell.covered ? (
                            <Link
                              to="/drill"
                              className="inline-block px-2 py-0.5 rounded-full text-xs font-bold tabular-nums transition-shadow hover:ring-2 hover:ring-(--accent) focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                              style={{ background: '#1d3a2a', color: '#7ee2a8' }}
                              title={t('drill.proveScenario')}
                              aria-label={t('drill.proveScenario')}
                            >
                              {cell.count}
                            </Link>
                          ) : (
                            <span
                              className="text-xs"
                              style={{ color: '#a04040' }}
                              title={t('coverageGaps.gap')}
                            >
                              —
                            </span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* [AUDIT #2] binding cloud-stub legend — required deliverable, not optional. */}
          <div
            className="rounded-xl border p-3 flex items-start gap-2 text-xs"
            style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--muted)' }}
          >
            <Info size={14} aria-hidden className="mt-0.5 shrink-0" />
            <span>{t('coverageGaps.cloudNote')}</span>
          </div>
        </>
      )}
    </div>
  );
}
