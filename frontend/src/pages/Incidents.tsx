import { useEffect, useMemo, useState } from 'react';
import { GitMerge, AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { apiGet, ApiError } from '../lib/api';
import DetailDrawer from '../components/DetailDrawer';
import { CritChip, toCrit } from '../lib/criticality';
import { toCsv, downloadCsv, downloadText, dateStamp, type CsvColumn } from '../lib/csv';

/* ──────────────────────────── Types ─────────────────────────────────────── */
interface IncidentHost { hostname: string; zone: string; criticality: string }
interface IncidentMember {
  scenario_id: string; name: string; severity: string; proximity: number;
  affected_hosts: string[]; latest_ts: string | null;
}
interface Incident {
  incident_id: string;
  size: number;
  members: IncidentMember[];
  members_truncated: boolean;
  hosts: IncidentHost[];
  techniques: string[];
  first_ts: string | null;
  last_ts: string | null;
  top_severity: string;
  max_proximity: number;
  score: number;
  relations: string[];
  honesty_note: string;
}
interface Rollup {
  incidents: number; clustered_detections: number; singletons: number;
  largest_incident_size: number; detections_total: number; truncated: boolean;
  honesty_note: string;
}
interface IncidentsResult { incidents: Incident[]; rollup: Rollup }

interface RespAction { action: string; from_scenarios: string[] }
interface RespValidate { engine: string; query: string; query_path: string | null; from_scenarios: string[] }
interface DrivingTactic { tactic: string; tactic_name: string }
interface IncidentResponse {
  incident_id: string;
  top_severity: string;
  member_count: number;
  driving_tactics: DrivingTactic[];
  hosts: IncidentHost[];
  sections: {
    contain: RespAction[]; eradicate: RespAction[]; recover: RespAction[]; validate: RespValidate[];
  };
  unresolved_scenarios: string[];
  note: string;
  honesty_note: string;
}
interface ResponsesResult { responses: IncidentResponse[]; honesty_note: string }

interface IncidentReport {
  incident_id: string;
  header: {
    incident_id: string; top_severity: string; max_proximity: number; score: number;
    member_count: number; host_count: number; technique_count: number;
    first_ts: string | null; last_ts: string | null; relations: string[]; members_truncated: boolean;
  };
  affected_assets: IncidentHost[];
  techniques: string[];
  detection_summary: IncidentMember[];
  response: IncidentResponse;
  source_notes: { incident: string; response: string };
  honesty_note: string;
  markdown: string;
}

interface FlatRow { section: string; action: string; from_scenarios: string }

const SEV_STYLE: Record<string, { bg: string; fg: string }> = {
  CRITICAL: { bg: '#71221c', fg: '#ffb4ab' },
  HIGH:     { bg: '#7a4a00', fg: '#ffd28a' },
  MEDIUM:   { bg: '#39402a', fg: '#d8e08a' },
  LOW:      { bg: '#23364a', fg: '#9fc7ef' },
};

function SevChip({ sev }: { sev: string }) {
  const s = SEV_STYLE[sev.toUpperCase()] ?? SEV_STYLE.LOW;
  return (
    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide"
          style={{ background: s.bg, color: s.fg }}>{sev}</span>
  );
}

/* ──────────────────────────── Page ──────────────────────────────────────── */
export default function Incidents() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const focused = searchParams.get('incident');

  const [data, setData] = useState<IncidentsResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [drawerMember, setDrawerMember] = useState<IncidentMember | null>(null);
  const [responses, setResponses] = useState<Map<string, IncidentResponse>>(new Map());
  const [responseIncidentId, setResponseIncidentId] = useState<string | null>(null);
  const [reportIncidentId, setReportIncidentId] = useState<string | null>(null);
  const [report, setReport] = useState<IncidentReport | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<IncidentsResult>('/api/incidents')
      .then((d) => { setData(d); setLoading(false); })
      .catch((e: unknown) => {
        setError(e instanceof ApiError ? e.message : t('incidents.failed'));
        setLoading(false);
      });
  }, [t]);

  useEffect(() => {
    apiGet<ResponsesResult>('/api/incident_response')
      .then((d) => setResponses(new Map(d.responses.map((r) => [r.incident_id, r]))))
      .catch(() => { /* response plan is best-effort; the page still works without it */ });
  }, []);

  // Pre-expand the deep-linked incident once data arrives.
  useEffect(() => {
    if (data && focused) setExpanded((prev) => new Set(prev).add(focused));
  }, [data, focused]);

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
    // keep the URL deep-link in sync with the currently-focused card
    setSearchParams((prev) => {
      const sp = new URLSearchParams(prev);
      if (sp.get('incident') === id) sp.delete('incident'); else sp.set('incident', id);
      return sp;
    });
  };

  const honesty = useMemo(
    () => data?.rollup.honesty_note ?? t('incidents.honesty'),
    [data, t],
  );

  const selectedResponse = responseIncidentId ? responses.get(responseIncidentId) ?? null : null;

  useEffect(() => {
    if (!reportIncidentId) { setReport(null); setReportError(null); return; }
    setReport(null); setReportError(null);
    apiGet<IncidentReport>(`/api/incident_report/${reportIncidentId}`)
      .then(setReport)
      .catch((e: unknown) => setReportError(e instanceof ApiError ? e.message : t('incidentReport.failed')));
  }, [reportIncidentId, t]);

  const exportResponseCsv = (r: IncidentResponse) => {
    const rows: FlatRow[] = [];
    (['contain', 'eradicate', 'recover'] as const).forEach((sec) => {
      r.sections[sec].forEach((a) =>
        rows.push({ section: sec, action: a.action, from_scenarios: a.from_scenarios.join(' ') }));
    });
    r.sections.validate.forEach((v) =>
      rows.push({ section: 'validate', action: `${v.engine}: ${v.query} (${v.query_path})`,
                  from_scenarios: v.from_scenarios.join(' ') }));
    const columns: CsvColumn<FlatRow>[] = [
      { header: t('incidentResponse.csv.section'), value: (x) => x.section },
      { header: t('incidentResponse.csv.action'), value: (x) => x.action },
      { header: t('incidentResponse.csv.fromScenarios'), value: (x) => x.from_scenarios },
    ];
    downloadCsv(`incident-response-${r.incident_id}-${dateStamp()}.csv`, toCsv(rows, columns));
  };

  return (
    <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <GitMerge size={18} aria-hidden /> {t('incidents.title')}
        </h1>
        <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>{t('incidents.subtitle')}</p>
      </div>

      {/* Persistent honesty panel — renders the API-supplied note verbatim. */}
      <p className="rounded-xl border p-3 text-xs italic flex items-start gap-2"
         style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--muted)' }}>
        <AlertTriangle size={14} aria-hidden style={{ flexShrink: 0, marginTop: 1 }} />
        {honesty}
      </p>

      {error && (
        <div className="rounded-xl border p-3 flex items-center gap-2 text-sm" role="alert"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}>
          <AlertTriangle size={14} aria-hidden /> {error}
        </div>
      )}

      {loading && <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('incidents.loading')}</p>}

      {data && !loading && (
        <div className="space-y-3">
          {/* Rollup band */}
          <div className="flex flex-wrap items-center gap-4 text-xs tabular-nums"
               style={{ color: 'var(--muted)' }}>
            <span>{t('incidents.rollup.incidents', { n: data.rollup.incidents })}</span>
            <span>{t('incidents.rollup.largest', { n: data.rollup.largest_incident_size })}</span>
            <span>{t('incidents.rollup.singletons', { n: data.rollup.singletons })}</span>
            <span>{t('incidents.rollup.total', { n: data.rollup.detections_total })}</span>
            {data.rollup.truncated && (
              <span className="italic">{t('incidents.rollup.truncated')}</span>
            )}
          </div>

          {data.incidents.length === 0 ? (
            <p className="text-xs italic" style={{ color: 'var(--muted)' }}>{t('incidents.empty')}</p>
          ) : (
            <div className="space-y-2.5">
              {data.incidents.map((inc) => {
                const open = expanded.has(inc.incident_id);
                return (
                  <div key={inc.incident_id} className="rounded-xl border"
                       style={{ borderColor: 'var(--border)', background: 'var(--panel)' }}>
                    <button type="button"
                            onClick={() => toggle(inc.incident_id)}
                            aria-expanded={open}
                            aria-label={t('incidents.expand', { id: inc.incident_id })}
                            className="w-full text-left px-3 py-2.5 flex flex-wrap items-center gap-2 cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)">
                      <span className="font-mono font-semibold" style={{ color: 'var(--fg)' }}>{inc.incident_id}</span>
                      <SevChip sev={inc.top_severity} />
                      <span className="text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                        {t('incidents.card.size', { n: inc.size })}
                      </span>
                      <span className="text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                        {t('incidents.card.score', { score: inc.score })}
                      </span>
                      <span className="flex flex-wrap items-center gap-1">
                        {inc.hosts.slice(0, 4).map((h) => (
                          <span key={h.hostname} className="flex items-center gap-1">
                            <span className="font-mono text-xs" style={{ color: 'var(--fg)' }}>{h.hostname}</span>
                            <CritChip level={toCrit(h.criticality)} />
                          </span>
                        ))}
                      </span>
                      <span className="flex flex-wrap items-center gap-1 ml-auto">
                        {inc.relations.map((r) => (
                          <span key={r} className="px-2 py-0.5 rounded-full text-[10px] font-medium"
                                style={{ background: 'var(--bg)', color: 'var(--muted)' }}>
                            {t(`incidents.relation.${r}`)}
                          </span>
                        ))}
                      </span>
                    </button>

                    {open && (
                      <div className="px-3 pb-3 space-y-2 border-t" style={{ borderColor: 'var(--border)' }}>
                        <div className="flex flex-wrap gap-1 pt-2">
                          {inc.techniques.map((tech) => (
                            <span key={tech} className="px-2 py-0.5 rounded-full text-[10px] font-mono"
                                  style={{ background: 'var(--bg)', color: 'var(--fg)' }}>{tech}</span>
                          ))}
                        </div>
                        <div className="text-[11px] tabular-nums" style={{ color: 'var(--muted)' }}>
                          {inc.first_ts && inc.last_ts
                            ? t('incidents.card.span', { from: inc.first_ts, to: inc.last_ts })
                            : t('incidents.card.spanEmpty')}
                        </div>
                        <div className="rounded-lg border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
                          <table className="w-full text-xs">
                            <thead style={{ background: 'var(--bg)' }}>
                              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                                <th className="px-2 py-1.5 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('incidents.member.scenario')}</th>
                                <th className="px-2 py-1.5 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('incidents.member.severity')}</th>
                                <th className="px-2 py-1.5 text-left font-medium" style={{ color: 'var(--muted)' }}>{t('incidents.member.proximity')}</th>
                              </tr>
                            </thead>
                            <tbody>
                              {inc.members.map((m) => (
                                <tr key={m.scenario_id}
                                    role="button"
                                    tabIndex={0}
                                    aria-label={t('incidents.member.inspect', { id: m.scenario_id })}
                                    onClick={() => setDrawerMember(m)}
                                    onKeyDown={(e) => {
                                      if (e.key === 'Enter' || e.key === ' ') {
                                        if (e.key === ' ') e.preventDefault();
                                        setDrawerMember(m);
                                      }
                                    }}
                                    className="cursor-pointer hover:bg-panel focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                                    style={{ borderBottom: '1px solid var(--border)' }}>
                                  <td className="px-2 py-1.5">
                                    <span className="font-mono" style={{ color: 'var(--fg)' }}>{m.scenario_id}</span>
                                    <span className="ml-2" style={{ color: 'var(--muted)' }}>{m.name}</span>
                                  </td>
                                  <td className="px-2 py-1.5"><SevChip sev={m.severity} /></td>
                                  <td className="px-2 py-1.5 tabular-nums" style={{ color: 'var(--muted)' }}>{m.proximity}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        {inc.members_truncated && (
                          <p className="text-[11px] italic" style={{ color: 'var(--muted)' }}>
                            {t('incidents.card.membersTruncated', { shown: inc.members.length, total: inc.size })}
                          </p>
                        )}
                        <button type="button"
                                onClick={() => setResponseIncidentId(inc.incident_id)}
                                className="mt-1 px-2.5 py-1 rounded-lg border text-xs font-medium cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                                style={{ borderColor: 'var(--border)', background: 'var(--bg)', color: 'var(--fg)' }}>
                          {t('incidentResponse.open')}
                        </button>
                        <button type="button"
                                onClick={() => setReportIncidentId(inc.incident_id)}
                                className="mt-1 ml-2 px-2.5 py-1 rounded-lg border text-xs font-medium cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                                style={{ borderColor: 'var(--border)', background: 'var(--bg)', color: 'var(--fg)' }}>
                          {t('incidentReport.open')}
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Member drill */}
      <DetailDrawer open={drawerMember != null} title={drawerMember?.scenario_id ?? ''} onClose={() => setDrawerMember(null)}>
        {drawerMember && (
          <div className="space-y-3 text-xs">
            <div style={{ color: 'var(--fg)' }}>{drawerMember.name}</div>
            <div className="flex items-center gap-2">
              <SevChip sev={drawerMember.severity} />
              <span className="tabular-nums" style={{ color: 'var(--muted)' }}>
                {t('incidents.member.proximity')}: {drawerMember.proximity}
              </span>
            </div>
            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>{t('incidents.member.hosts')}</div>
              <div className="flex flex-wrap gap-1">
                {drawerMember.affected_hosts.map((h) => (
                  <span key={h} className="px-2 py-0.5 rounded-full text-[10px] font-mono"
                        style={{ background: 'var(--panel)', color: 'var(--fg)' }}>{h}</span>
                ))}
              </div>
            </div>
            <div>
              <div className="uppercase tracking-wide" style={{ color: 'var(--muted)' }}>{t('incidents.member.latestTs')}</div>
              <div className="mt-0.5 tabular-nums" style={{ color: 'var(--fg)' }}>{drawerMember.latest_ts ?? '—'}</div>
            </div>
          </div>
        )}
      </DetailDrawer>

      {/* Consolidated response plan */}
      <DetailDrawer
        open={selectedResponse != null}
        title={t('incidentResponse.drawerTitle', { id: responseIncidentId ?? '' })}
        onClose={() => setResponseIncidentId(null)}>
        {selectedResponse && (
          <div className="space-y-3 text-xs">
            {/* driving tactics */}
            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>
                {t('incidentResponse.derivedFrom')}
              </div>
              <div className="flex flex-wrap gap-1">
                {selectedResponse.driving_tactics.map((d) => (
                  <span key={d.tactic} className="px-2 py-0.5 rounded-full text-[10px] font-medium"
                        style={{ background: 'var(--panel)', color: 'var(--fg)' }}>
                    {d.tactic} · {d.tactic_name}
                  </span>
                ))}
              </div>
            </div>
            {/* scoped hosts */}
            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>
                {t('incidentResponse.scopedHosts')}
              </div>
              <div className="flex flex-wrap gap-1">
                {selectedResponse.hosts.map((h) => (
                  <span key={h.hostname} className="flex items-center gap-1">
                    <span className="font-mono" style={{ color: 'var(--fg)' }}>{h.hostname}</span>
                    <CritChip level={toCrit(h.criticality)} />
                  </span>
                ))}
              </div>
            </div>
            {/* four sections */}
            {(['contain', 'eradicate', 'recover'] as const).map((sec) => (
              <div key={sec}>
                <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>
                  {t(`incidentResponse.section.${sec}`)}
                </div>
                <ul className="space-y-1">
                  {selectedResponse.sections[sec].map((a) => (
                    <li key={a.action} className="flex flex-col gap-0.5">
                      <span style={{ color: 'var(--fg)' }}>{a.action}</span>
                      <span className="flex flex-wrap items-center gap-1">
                        <span style={{ color: 'var(--muted)' }}>{t('incidentResponse.fromScenarios')}</span>
                        {a.from_scenarios.map((s) => (
                          <span key={s} className="px-1.5 py-0.5 rounded-full text-[10px] font-mono"
                                style={{ background: 'var(--panel)', color: 'var(--fg)' }}>{s}</span>
                        ))}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>
                {t('incidentResponse.section.validate')}
              </div>
              <ul className="space-y-1">
                {selectedResponse.sections.validate.map((v) => (
                  <li key={`${v.engine}|${v.query}|${v.query_path}`} className="flex flex-col gap-0.5">
                    <span className="font-mono" style={{ color: 'var(--fg)' }}>
                      {v.engine}: {v.query} ({v.query_path})
                    </span>
                    <span className="flex flex-wrap items-center gap-1">
                      <span style={{ color: 'var(--muted)' }}>{t('incidentResponse.fromScenarios')}</span>
                      {v.from_scenarios.map((s) => (
                        <span key={s} className="px-1.5 py-0.5 rounded-full text-[10px] font-mono"
                              style={{ background: 'var(--panel)', color: 'var(--fg)' }}>{s}</span>
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
            {selectedResponse.unresolved_scenarios.length > 0 && (
              <p className="italic" style={{ color: 'var(--muted)' }}>
                {t('incidentResponse.unresolved', { ids: selectedResponse.unresolved_scenarios.join(', ') })}
              </p>
            )}
            <button type="button"
                    onClick={() => exportResponseCsv(selectedResponse)}
                    className="px-2.5 py-1 rounded-lg border text-xs font-medium cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                    style={{ borderColor: 'var(--border)', background: 'var(--bg)', color: 'var(--fg)' }}>
              {t('incidentResponse.csv.export')}
            </button>
            {/* persistent honesty panel — verbatim from the payload */}
            <p className="rounded-lg border p-2 italic flex items-start gap-2"
               style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--muted)' }}>
              <AlertTriangle size={12} aria-hidden style={{ flexShrink: 0, marginTop: 1 }} />
              {selectedResponse.honesty_note}
            </p>
          </div>
        )}
      </DetailDrawer>

      {/* Post-incident report */}
      <DetailDrawer
        open={reportIncidentId != null}
        title={t('incidentReport.drawerTitle', { id: reportIncidentId ?? '' })}
        onClose={() => setReportIncidentId(null)}>
        {reportError && (
          <p className="text-xs" style={{ color: '#ffb4ab' }}>{reportError}</p>
        )}
        {report && (
          <div className="space-y-3 text-xs">
            {/* header */}
            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>
                {t('incidentReport.header')}
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 tabular-nums" style={{ color: 'var(--fg)' }}>
                <span style={{ color: 'var(--muted)' }}>{t('incidentReport.fields.topSeverity')}</span>
                <span>{report.header.top_severity}</span>
                <span style={{ color: 'var(--muted)' }}>{t('incidentReport.fields.score')}</span>
                <span>{report.header.score}</span>
                <span style={{ color: 'var(--muted)' }}>{t('incidentReport.fields.maxProximity')}</span>
                <span>{report.header.max_proximity}</span>
                <span style={{ color: 'var(--muted)' }}>{t('incidentReport.fields.members')}</span>
                <span>{report.header.member_count}</span>
                <span style={{ color: 'var(--muted)' }}>{t('incidentReport.fields.hosts')}</span>
                <span>{report.header.host_count}</span>
                <span style={{ color: 'var(--muted)' }}>{t('incidentReport.fields.techniques')}</span>
                <span>{report.header.technique_count}</span>
                <span style={{ color: 'var(--muted)' }}>{t('incidentReport.fields.span')}</span>
                <span>{report.header.first_ts ?? '—'} → {report.header.last_ts ?? '—'}</span>
              </div>
              {report.header.members_truncated && (
                <p className="italic mt-1" style={{ color: 'var(--muted)' }}>
                  {t('incidentReport.membersTruncated',
                     { shown: report.detection_summary.length, total: report.header.member_count })}
                </p>
              )}
            </div>
            {/* affected assets */}
            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>
                {t('incidentReport.affectedAssets')}
              </div>
              <div className="flex flex-wrap gap-1">
                {report.affected_assets.map((h) => (
                  <span key={h.hostname} className="flex items-center gap-1">
                    <span className="font-mono" style={{ color: 'var(--fg)' }}>{h.hostname}</span>
                    <CritChip level={toCrit(h.criticality)} />
                  </span>
                ))}
              </div>
            </div>
            {/* techniques */}
            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>
                {t('incidentReport.techniques')}
              </div>
              <div className="flex flex-wrap gap-1">
                {report.techniques.map((tech) => (
                  <span key={tech} className="px-2 py-0.5 rounded-full text-[10px] font-mono"
                        style={{ background: 'var(--panel)', color: 'var(--fg)' }}>{tech}</span>
                ))}
              </div>
            </div>
            {/* detection summary */}
            <div>
              <div className="uppercase tracking-wide mb-1" style={{ color: 'var(--muted)' }}>
                {t('incidentReport.detectionSummary')}
              </div>
              <ul className="space-y-1">
                {report.detection_summary.map((m) => (
                  <li key={m.scenario_id} className="flex items-center gap-2">
                    <span className="font-mono" style={{ color: 'var(--fg)' }}>{m.scenario_id}</span>
                    <SevChip sev={m.severity} />
                    <span className="tabular-nums" style={{ color: 'var(--muted)' }}>{m.proximity}</span>
                  </li>
                ))}
              </ul>
            </div>
            {/* download */}
            <button type="button"
                    onClick={() => downloadText(
                      `augur-incident-${report.incident_id}.md`, report.markdown, 'text/markdown')}
                    className="px-2.5 py-1 rounded-lg border text-xs font-medium cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
                    style={{ borderColor: 'var(--border)', background: 'var(--bg)', color: 'var(--fg)' }}>
              {t('incidentReport.download')}
            </button>
            {/* honesty panel — verbatim from the payload */}
            <p className="rounded-lg border p-2 italic flex items-start gap-2"
               style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--muted)' }}>
              <AlertTriangle size={12} aria-hidden style={{ flexShrink: 0, marginTop: 1 }} />
              {report.honesty_note}
            </p>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
