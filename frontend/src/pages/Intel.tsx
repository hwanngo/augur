import { useMemo, useState } from 'react';
import { ScanSearch, AlertTriangle, CheckCircle2, XCircle, FileText, ListChecks } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { apiPost, ApiError } from '../lib/api';
import ExportCsvButton from '../components/ExportCsvButton';
import { toCsv, downloadCsv, dateStamp, type CsvColumn } from '../lib/csv';
import { CritChip, toCrit } from '../lib/criticality';

/* ──────────────────────────── Types ─────────────────────────────────────── */
interface IocInput { type: string; value: string }

interface ExtractItem {
  type: string;
  value: string;
  category: string;
  confidence: string;
  matchable: boolean;
  defanged_from?: string;
  reason?: string;
}
interface ExtractResult {
  summary: {
    extracted_total: number;
    matchable_count: number;
    unmatchable_count: number;
    truncated: boolean;
    honesty_note: string;
  };
  matchable: ExtractItem[];
  unmatchable: ExtractItem[];
}

interface EventHit {
  host: string;
  timestamp: string;
  label: string;
  matched_field: string;
  snippet: string;
}
interface ScenarioHit {
  scenario_id: string;
  name: string;
  proximity: number;
  affected_hosts: string[];
}
interface IocResult {
  type: string;
  value: string;
  target: 'event' | 'scenario';
  matched: boolean;
  hit_count: number;
  hits: (EventHit | ScenarioHit)[];
  truncated: boolean;
  covered?: boolean;
  covered_scenarios?: string[];
}
interface HostRollup {
  hostname: string;
  zone: string;
  criticality: string;
  ioc_count: number;
  types: string[];
}
interface IocSummary {
  iocs_total: number;
  iocs_matched: number;
  hosts_touched: number;
  honesty_note: string;
}
interface IocMatchResult {
  summary: IocSummary;
  iocs: IocResult[];
  hosts: HostRollup[];
}

/* ──────────────────────────── Parsing ───────────────────────────────────── */
// Split on the FIRST colon only — values may contain `:` (e.g. file paths).
function parseIocs(text: string): IocInput[] {
  const out: IocInput[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    const type = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!type || !value) continue;
    out.push({ type, value });
  }
  return out;
}

function timeOnly(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function truncate(s: string, max = 80): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}


/* ──────────────────────────── CSV export ────────────────────────────────── */
interface ExportRow { ioc: IocResult; hit: EventHit }
const EXPORT_COLUMNS: CsvColumn<ExportRow>[] = [
  { header: 'ioc_type', value: (r) => r.ioc.type },
  { header: 'ioc_value', value: (r) => r.ioc.value },
  { header: 'host', value: (r) => r.hit.host },
  { header: 'timestamp', value: (r) => r.hit.timestamp },
  { header: 'matched_field', value: (r) => r.hit.matched_field },
  { header: 'snippet', value: (r) => r.hit.snippet },
];

/* ──────────────────────────── Intel page ────────────────────────────────── */
export default function Intel() {
  const { t } = useTranslation();
  const [text, setText] = useState('');
  const [result, setResult] = useState<IocMatchResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [mode, setMode] = useState<'manual' | 'paste'>('manual');
  const [reportText, setReportText] = useState('');
  const [extract, setExtract] = useState<ExtractResult | null>(null);
  const [extracting, setExtracting] = useState(false);
  const [extractError, setExtractError] = useState<string | null>(null);

  const runExtract = () => {
    if (!reportText.trim()) return;
    setExtracting(true); setExtractError(null); setExtract(null);
    apiPost<ExtractResult>('/api/ioc_extract', { text: reportText })
      .then(setExtract)
      .catch((e: unknown) => setExtractError(e instanceof ApiError ? e.message : t('intel.extract.failed')))
      .finally(() => setExtracting(false));
  };

  const pushToWatchlist = () => {
    if (!extract) return;
    const existing = new Set(parseIocs(text).map((i) => `${i.type}:${i.value}`.toLowerCase()));
    const lines: string[] = [];
    for (const i of extract.matchable) {
      const line = `${i.type}:${i.value}`;
      if (!existing.has(line.toLowerCase())) { existing.add(line.toLowerCase()); lines.push(line); }
    }
    if (lines.length === 0) return;
    setText((prev) => (prev.trim() ? `${prev.replace(/\n+$/, '')}\n${lines.join('\n')}` : lines.join('\n')));
    setMode('manual');
  };

  const UNMATCH_COLUMNS: CsvColumn<ExtractItem>[] = [
    { header: 'type', value: (r) => r.type },
    { header: 'value', value: (r) => r.value },
    { header: 'category', value: (r) => r.category },
    { header: 'defanged_from', value: (r) => r.defanged_from ?? '' },
    { header: 'reason', value: (r) => r.reason ?? '' },
  ];
  const onExportUnmatchable = () => {
    if (!extract || extract.unmatchable.length === 0) return;
    downloadCsv(`augur-iocs-unmatchable-${dateStamp()}.csv`, toCsv(extract.unmatchable, UNMATCH_COLUMNS));
  };

  const iocs = useMemo(() => parseIocs(text), [text]);

  const eventIocs = useMemo(() => result?.iocs.filter((i) => i.target === 'event') ?? [], [result]);
  const techniqueIocs = result?.iocs.filter((i) => i.target === 'scenario') ?? [];

  const eventHitRows = useMemo<ExportRow[]>(() => {
    const rows: ExportRow[] = [];
    for (const ioc of eventIocs) {
      for (const hit of ioc.hits as EventHit[]) rows.push({ ioc, hit });
    }
    return rows;
  }, [eventIocs]);

  const run = () => {
    if (iocs.length === 0) return;
    setRunning(true); setError(null); setResult(null);
    apiPost<IocMatchResult>('/api/ioc_match', { iocs })
      .then(setResult)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : t('intel.failed')))
      .finally(() => setRunning(false));
  };

  const onExport = () => {
    if (eventHitRows.length === 0) return;
    downloadCsv(`augur-intel-${dateStamp()}.csv`, toCsv(eventHitRows, EXPORT_COLUMNS));
  };

  return (
    <div className="w-full max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
            <ScanSearch size={18} aria-hidden /> {t('intel.title')}
          </h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{t('intel.subtitle')}</p>
        </div>
        {eventHitRows.length > 0 && <ExportCsvButton onExport={onExport} label={t('intel.export')} />}
      </div>

      {/* Mode toggle */}
      <div className="flex gap-2" role="tablist" aria-label="intel-mode">
        <button type="button" role="tab" aria-selected={mode === 'manual'} onClick={() => setMode('manual')}
                className="px-3 py-1.5 text-xs rounded-lg border flex items-center gap-1.5"
                style={{ background: mode === 'manual' ? 'var(--panel)' : 'var(--bg)',
                         borderColor: 'var(--border)', color: 'var(--fg)' }}>
          <ListChecks size={13} aria-hidden /> {t('intel.mode.manual')}
        </button>
        <button type="button" role="tab" aria-selected={mode === 'paste'} onClick={() => setMode('paste')}
                className="px-3 py-1.5 text-xs rounded-lg border flex items-center gap-1.5"
                style={{ background: mode === 'paste' ? 'var(--panel)' : 'var(--bg)',
                         borderColor: 'var(--border)', color: 'var(--fg)' }}>
          <FileText size={13} aria-hidden /> {t('intel.mode.paste')}
        </button>
      </div>

      {/* Paste-report mode */}
      {mode === 'paste' && (
        <div className="space-y-4">
          <label className="flex flex-col gap-1.5 text-xs" style={{ color: 'var(--muted)' }}>
            {t('intel.extract.inputLabel')}
            <textarea
              aria-label={t('intel.extract.inputLabel')}
              value={reportText}
              onChange={(e) => setReportText(e.target.value)}
              rows={8}
              placeholder={t('intel.extract.placeholder')}
              className="px-3 py-2 text-xs rounded-lg border resize-y"
              style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
            />
          </label>
          <button type="button" onClick={runExtract} disabled={!reportText.trim() || extracting}
                  className="btn-primary px-3 py-1.5 text-xs rounded-lg flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed">
            {extracting ? t('intel.extract.running') : t('intel.extract.run')}
          </button>

          {extractError && (
            <div className="rounded-xl border p-3 flex items-center gap-2 text-sm" role="alert"
                 style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}>
              <AlertTriangle size={14} aria-hidden /> {extractError}
            </div>
          )}

          {extract && (
            <div className="space-y-4">
              <p className="rounded-xl border p-3 text-xs italic"
                 style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--muted)' }}>
                {t('intel.extract.honesty', { matchable: extract.summary.matchable_count,
                                              unmatchable: extract.summary.unmatchable_count })}
              </p>
              {extract.summary.truncated && (
                <p className="text-xs italic" style={{ color: 'var(--muted)' }}>
                  {t('intel.extract.truncated', { count: extract.summary.extracted_total })}
                </p>
              )}

              {/* Matchable */}
              <div className="space-y-2">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <h2 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
                    {t('intel.extract.matchableSection', { count: extract.summary.matchable_count })}
                  </h2>
                  {extract.matchable.length > 0 && (
                    <button type="button" onClick={pushToWatchlist}
                            className="btn-primary px-3 py-1.5 text-xs rounded-lg">
                      {t('intel.extract.push')}
                    </button>
                  )}
                </div>
                {extract.matchable.length === 0
                  ? <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{t('intel.extract.noneMatchable')}</p>
                  : (
                  <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
                    <table className="w-full min-w-[480px] text-xs">
                      <thead style={{ background: 'var(--panel)' }}>
                        <tr style={{ borderBottom: '1px solid var(--border)' }}>
                          <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.extract.cols.type')}</th>
                          <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.extract.cols.value')}</th>
                          <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.extract.cols.category')}</th>
                          <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.extract.cols.confidence')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {extract.matchable.map((i) => (
                          <tr key={`${i.type}:${i.value}`} style={{ borderBottom: '1px solid var(--border)' }}>
                            <td className="px-3 py-2 font-mono" style={{ color: 'var(--fg)' }}>{i.type}</td>
                            <td className="px-3 py-2 font-mono" style={{ color: 'var(--fg)' }}>{i.value}</td>
                            <td className="px-3 py-2" style={{ color: 'var(--muted)' }}>{i.category}</td>
                            <td className="px-3 py-2" style={{ color: 'var(--muted)' }}>{i.confidence}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Unmatchable */}
              <div className="space-y-2">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <h2 className="text-sm font-semibold flex items-center gap-1.5" style={{ color: '#ffd28a' }}>
                    <AlertTriangle size={14} aria-hidden />
                    {t('intel.extract.unmatchableSection', { count: extract.summary.unmatchable_count })}
                  </h2>
                  {extract.unmatchable.length > 0 && <ExportCsvButton onExport={onExportUnmatchable} label={t('intel.export')} />}
                </div>
                {extract.unmatchable.length === 0
                  ? <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{t('intel.extract.noneUnmatchable')}</p>
                  : (
                  <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
                    <table className="w-full min-w-[640px] text-xs">
                      <thead style={{ background: 'var(--panel)' }}>
                        <tr style={{ borderBottom: '1px solid var(--border)' }}>
                          <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.extract.cols.type')}</th>
                          <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.extract.cols.value')}</th>
                          <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.extract.cols.category')}</th>
                          <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.extract.cols.defanged')}</th>
                          <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.extract.cols.reason')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {extract.unmatchable.map((i) => (
                          <tr key={`${i.type}:${i.value}`} style={{ borderBottom: '1px solid var(--border)' }}>
                            <td className="px-3 py-2 font-mono" style={{ color: 'var(--fg)' }}>{i.type}</td>
                            <td className="px-3 py-2 font-mono" style={{ color: 'var(--fg)' }}>{i.value}</td>
                            <td className="px-3 py-2" style={{ color: 'var(--muted)' }}>{i.category}</td>
                            <td className="px-3 py-2 font-mono" style={{ color: 'var(--muted)' }}>{i.defanged_from ?? '—'}</td>
                            <td className="px-3 py-2" style={{ color: 'var(--muted)' }}>{i.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Input — manual watchlist mode */}
      {mode === 'manual' && (
      <div className="space-y-2">
        <label className="flex flex-col gap-1.5 text-xs" style={{ color: 'var(--muted)' }}>
          {t('intel.inputLabel')}
          <textarea
            aria-label={t('intel.inputLabel')}
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={5}
            placeholder={t('intel.placeholder')}
            className="px-3 py-2 text-xs rounded-lg border font-mono resize-y"
            style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--fg)' }}
          />
        </label>
        <p className="text-xs" style={{ color: 'var(--muted)' }}>
          {t('intel.validTypes')} <span className="italic">{t('intel.unsupportedNote')}</span>
        </p>
        <button type="button" onClick={run} disabled={iocs.length === 0 || running}
                className="btn-primary px-3 py-1.5 text-xs rounded-lg flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed">
          {running && (
            <span className="w-3 h-3 rounded-full border-2 animate-spin"
                  style={{ borderColor: 'rgba(0,0,0,0.25)', borderTopColor: '#0d1117' }} aria-hidden />
          )}
          {running ? t('intel.running') : t('intel.run')}
        </button>
      </div>
      )}

      {error && (
        <div className="rounded-xl border p-3 flex items-center gap-2 text-sm" role="alert"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}>
          <AlertTriangle size={14} aria-hidden /> {error}
        </div>
      )}

      {result && (
        <div className="space-y-5">
          {/* Summary */}
          <div className="text-sm font-semibold tabular-nums" style={{ color: 'var(--fg)' }}>
            {t('intel.summary', {
              matched: result.summary.iocs_matched,
              total: result.summary.iocs_total,
              hosts: result.summary.hosts_touched,
            })}
          </div>

          {/* Honesty note — persistent panel */}
          {result.summary.honesty_note && (
            <p className="rounded-xl border p-3 text-xs italic"
               style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--muted)' }}>
              {result.summary.honesty_note}
            </p>
          )}

          {/* Event IOCs */}
          {eventIocs.map((ioc) => (
            <div key={`${ioc.type}:${ioc.value}`} className="rounded-xl border overflow-hidden"
                 style={{ borderColor: 'var(--border)' }}>
              <div className="px-4 py-3 flex items-center gap-3 flex-wrap" style={{ background: 'var(--panel)' }}>
                <span className="font-mono text-xs" style={{ color: 'var(--fg)' }}>{ioc.type}:{ioc.value}</span>
                {ioc.matched
                  ? <span className="flex items-center gap-1 text-xs font-semibold" style={{ color: '#7ee787' }}>
                      <CheckCircle2 size={13} aria-hidden /> {t('intel.matched')}
                    </span>
                  : <span className="flex items-center gap-1 text-xs font-semibold" style={{ color: 'var(--muted)' }}>
                      <XCircle size={13} aria-hidden /> {t('intel.noMatch')}
                    </span>}
                <span className="text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                  {t('intel.hits', { count: ioc.hit_count })}
                </span>
              </div>
              {ioc.matched && ioc.hits.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[640px] text-xs">
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)' }}>
                        <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.eventHits.host')}</th>
                        <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.eventHits.time')}</th>
                        <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.eventHits.label')}</th>
                        <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.eventHits.field')}</th>
                        <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.eventHits.snippet')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(ioc.hits as EventHit[]).map((h, i) => (
                        <tr key={`${h.host}-${h.timestamp}-${i}`} style={{ borderBottom: '1px solid var(--border)' }}>
                          <td className="px-3 py-2 font-mono" style={{ color: 'var(--fg)' }}>{h.host}</td>
                          <td className="px-3 py-2 tabular-nums" style={{ color: 'var(--muted)' }}>{timeOnly(h.timestamp)}</td>
                          <td className="px-3 py-2" style={{ color: 'var(--muted)' }}>{h.label}</td>
                          <td className="px-3 py-2 font-mono" style={{ color: 'var(--muted)' }}>{h.matched_field}</td>
                          <td className="px-3 py-2 font-mono" style={{ color: 'var(--muted)' }} title={h.snippet}>{truncate(h.snippet)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {ioc.truncated && (
                    <p className="px-3 py-2 text-xs italic" style={{ color: 'var(--muted)' }}>
                      {t('intel.truncated', { total: ioc.hit_count })}
                    </p>
                  )}
                </div>
              )}
            </div>
          ))}

          {/* Technique coverage */}
          {techniqueIocs.length > 0 && (
            <div className="space-y-3">
              <div>
                <h2 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>{t('intel.techniqueSection')}</h2>
                <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{t('intel.techniqueNote')}</p>
              </div>
              {techniqueIocs.map((ioc) => {
                const hits = ioc.hits as ScenarioHit[];
                return (
                  <div key={`${ioc.type}:${ioc.value}`} className="rounded-xl border overflow-hidden"
                       style={{ borderColor: 'var(--border)' }}>
                    <div className="px-4 py-3 flex items-center gap-3 flex-wrap" style={{ background: 'var(--panel)' }}>
                      <span className="font-mono text-xs" style={{ color: 'var(--fg)' }}>{ioc.type}:{ioc.value}</span>
                      {ioc.covered
                        ? <span className="flex items-center gap-1 text-xs font-semibold" style={{ color: '#7ee787' }}>
                            <CheckCircle2 size={13} aria-hidden /> {t('intel.covered')}
                          </span>
                        : <span className="flex items-center gap-1 text-xs font-semibold" style={{ color: 'var(--muted)' }}>
                            <XCircle size={13} aria-hidden /> {t('intel.notCovered')}
                          </span>}
                    </div>
                    {hits.length > 0 && (
                      <div className="overflow-x-auto">
                        <table className="w-full min-w-[560px] text-xs">
                          <thead>
                            <tr style={{ borderBottom: '1px solid var(--border)' }}>
                              <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.fired.scenario')}</th>
                              <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.fired.name')}</th>
                              <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.fired.proximity')}</th>
                              <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.fired.hosts')}</th>
                            </tr>
                          </thead>
                          <tbody>
                            {hits.map((h) => (
                              <tr key={h.scenario_id} style={{ borderBottom: '1px solid var(--border)' }}>
                                <td className="px-3 py-2 font-mono" style={{ color: 'var(--fg)' }}>{h.scenario_id}</td>
                                <td className="px-3 py-2" style={{ color: 'var(--muted)' }}>{h.name}</td>
                                <td className="px-3 py-2 tabular-nums" style={{ color: 'var(--muted)' }}>{h.proximity.toFixed(2)}</td>
                                <td className="px-3 py-2" style={{ color: 'var(--muted)' }}>{h.affected_hosts.join(', ')}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Hosts rollup */}
          {result.hosts.length > 0 && (
            <div className="space-y-2">
              <h2 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>{t('intel.hostsSection')}</h2>
              <div className="rounded-xl border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
                <table className="w-full min-w-[560px] text-xs">
                  <thead style={{ background: 'var(--panel)' }}>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.hostsTable.host')}</th>
                      <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.hostsTable.zone')}</th>
                      <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.hostsTable.criticality')}</th>
                      <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.hostsTable.iocCount')}</th>
                      <th className="px-3 py-2 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('intel.hostsTable.types')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.hosts.map((h) => (
                      <tr key={h.hostname} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td className="px-3 py-2 font-mono" style={{ color: 'var(--fg)' }}>{h.hostname}</td>
                        <td className="px-3 py-2" style={{ color: 'var(--muted)' }}>{h.zone}</td>
                        <td className="px-3 py-2"><CritChip level={toCrit(h.criticality)} /></td>
                        <td className="px-3 py-2 tabular-nums" style={{ color: 'var(--muted)' }}>{h.ioc_count}</td>
                        <td className="px-3 py-2" style={{ color: 'var(--muted)' }}>{h.types.join(', ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
