import { useEffect, useMemo, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Crosshair, AlertTriangle } from 'lucide-react';
import { apiGet, apiPost, ApiError } from '../lib/api';
import DetectionCard, { type Detection } from '../components/DetectionCard';
import Dropdown from '../components/Dropdown';

interface ScenarioRow {
  scenario_id: string;
  name: string;
  os_family: string;
  applicable_zones: string[];
  synthesizable: boolean;
}
interface Asset { hostname: string; os: string; zone: string; }
interface Topology { zones: string[]; assets: Asset[]; }
interface FeedSummary { total_events: number; baseline_events: number; injected_events: number; }
interface DrillResult {
  scenario_id: string;
  host: string | null;
  detection: Detection | null;
  feed_summary: FeedSummary | null;
  mode: 'inject' | 'replay';
  note: string;
  replay_hosts?: string[];
}

// Client-side OS family mapping — mirrors metrics.coverage._os_to_family substring order.
function osToFamily(os: string): string | null {
  const s = os.toLowerCase();
  if (s.includes('windows')) return 'windows';
  if (s.includes('linux')) return 'linux';
  if (s.includes('mac')) return 'macos';
  return null;
}

export default function Drill() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [scenarios, setScenarios] = useState<ScenarioRow[]>([]);
  const [topology, setTopology] = useState<Topology | null>(null);
  const [scenarioId, setScenarioId] = useState('');
  const [host, setHost] = useState('');
  const [result, setResult] = useState<DrillResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<ScenarioRow[]>('/api/scenarios').then(setScenarios).catch(() => {});
    apiGet<Topology>('/api/topology').then(setTopology).catch(() => {});
  }, []);

  // ?scenario_id= preselect (once scenarios load).
  useEffect(() => {
    const pre = params.get('scenario_id');
    if (pre && scenarios.some((s) => s.scenario_id === pre)) setScenarioId(pre);
  }, [params, scenarios]);

  const selected = scenarios.find((s) => s.scenario_id === scenarioId) ?? null;
  // Replay mode for non-synthesizable scenarios: no host choice, no synth feed.
  const replayMode = selected != null && !selected.synthesizable;

  // [AUDIT #1] host options = assets whose OS family matches AND whose zone ∈ applicable_zones.
  const hostOptions = useMemo(() => {
    if (!selected || !topology) return [];
    const zones = new Set(selected.applicable_zones);
    return topology.assets.filter(
      (a) => osToFamily(a.os) === selected.os_family && zones.has(a.zone),
    );
  }, [selected, topology]);

  // Reset host if it falls out of the eligible set.
  useEffect(() => {
    if (host && !hostOptions.some((a) => a.hostname === host)) setHost('');
  }, [hostOptions, host]);

  const runDrill = () => {
    if (!scenarioId) return;
    if (!replayMode && !host) return;           // synth requires a host; replay ignores it
    setRunning(true); setError(null); setResult(null);
    // Replay ignores host server-side; send "" to satisfy the required-string body schema.
    apiPost<DrillResult>('/api/drill', { scenario_id: scenarioId, host: replayMode ? '' : host })
      .then(setResult)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : t('drill.failed')))
      .finally(() => setRunning(false));
  };

  const det = result?.detection ?? null;
  const pct = det ? Math.round(det.proximity * 100) : 0;
  const isReplayResult = result?.mode === 'replay';

  return (
    <div className="w-full max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-5">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
          <Crosshair size={18} aria-hidden /> {t('drill.title')}
        </h1>
        <p className="text-xs mt-0.5" style={{ color: 'var(--muted)' }}>
          {replayMode ? t('drill.replaySubtitle') : t('drill.subtitle')}
        </p>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
          {t('drill.selectScenario')}
          <Dropdown
            aria-label={t('drill.selectScenario')}
            value={scenarioId}
            onChange={setScenarioId}
            placeholder="—"
            options={scenarios.map((s) => ({ value: s.scenario_id, label: `${s.scenario_id} · ${s.name}` }))}
          />
        </label>

        {!replayMode && (
          <label className="flex flex-col gap-1 text-xs" style={{ color: 'var(--muted)' }}>
            {t('drill.selectHost')}
            <Dropdown
              aria-label={t('drill.selectHost')}
              value={host}
              onChange={setHost}
              disabled={!selected}
              placeholder="—"
              options={hostOptions.map((a) => ({ value: a.hostname, label: a.hostname }))}
            />
          </label>
        )}

        <button type="button" onClick={runDrill}
                disabled={!scenarioId || (!replayMode && !host) || running}
                className="btn-primary px-3 py-1.5 text-xs rounded-lg flex items-center gap-2">
          {running && (
            <span
              className="w-3 h-3 rounded-full border-2 animate-spin"
              style={{ borderColor: 'rgba(0,0,0,0.25)', borderTopColor: '#0d1117' }}
              aria-hidden
            />
          )}
          {running
            ? (replayMode ? t('drill.replayRunning') : t('drill.running'))
            : (replayMode ? t('drill.replay') : t('drill.run'))}
        </button>
      </div>

      {!replayMode && selected && hostOptions.length === 0 && (
        <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('drill.noHostForOs')}</p>
      )}

      {error && (
        <div className="rounded-xl border p-3 flex items-center gap-2 text-sm" role="alert"
             style={{ background: '#2a1a1a', borderColor: '#a02020', color: '#ffb4ab' }}>
          <AlertTriangle size={14} aria-hidden /> {error}
        </div>
      )}

      {result && (
        <div className="space-y-3">
          <div className="text-sm font-semibold" style={{ color: det ? 'var(--accent)' : 'var(--muted)' }}>
            {det
              ? `✓ ${t('drill.detectedAt', { pct })}`
              : (isReplayResult ? t('drill.replayNotPresent') : t('drill.notDetected'))}
          </div>
          {det && (
            <DetectionCard
              d={det}
              onOpenCase={(x) => navigate(`/timeline?scenario_id=${encodeURIComponent(x.scenario_id)}`)}
              onPivot={(x) => navigate(`/pivot?detection=${encodeURIComponent(x.scenario_id)}`)}
            />
          )}
          {isReplayResult ? (
            <div className="space-y-1">
              <p className="text-xs" style={{ color: 'var(--muted)' }}>{t('drill.replayNote')}</p>
              {result.replay_hosts && result.replay_hosts.length > 0 && (
                <p className="text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                  {t('drill.replayMatchedOn', { hosts: result.replay_hosts.join(', ') })}
                </p>
              )}
            </div>
          ) : (
            result.feed_summary && (
              <p className="text-xs tabular-nums" style={{ color: 'var(--muted)' }}>
                {t('drill.feedSummary', {
                  total: result.feed_summary.total_events,
                  baseline: result.feed_summary.baseline_events,
                  injected: result.feed_summary.injected_events,
                })}
              </p>
            )
          )}
        </div>
      )}
    </div>
  );
}
