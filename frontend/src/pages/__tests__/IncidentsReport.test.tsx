import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Incidents from '../Incidents';
import * as api from '../../lib/api';
import * as csv from '../../lib/csv';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k) }),
}));

const INCIDENTS = {
  incidents: [{
    incident_id: 'INC-0001', size: 1,
    members: [{ scenario_id: 'SCEN-WIN-001', name: 'Win', severity: 'CRITICAL',
                proximity: 1.0, affected_hosts: ['HOST-A'], latest_ts: '2026-01-01T00:00:00+00:00' }],
    members_truncated: false,
    hosts: [{ hostname: 'HOST-A', zone: 'User_Endpoint', criticality: 'CRITICAL' }],
    techniques: ['T1059'], first_ts: '2026-01-01T00:00:00+00:00', last_ts: '2026-01-01T00:00:00+00:00',
    top_severity: 'CRITICAL', max_proximity: 1.0, score: 4.0, relations: [], honesty_note: 'inc note',
  }],
  rollup: { incidents: 1, clustered_detections: 0, singletons: 1, largest_incident_size: 1,
            detections_total: 1, truncated: false, honesty_note: 'roll note' },
};
const RESPONSES = { responses: [], honesty_note: 'resp note' };
const REPORT = {
  incident_id: 'INC-0001',
  header: { incident_id: 'INC-0001', top_severity: 'CRITICAL', max_proximity: 1.0, score: 4.0,
            member_count: 1, host_count: 1, technique_count: 1,
            first_ts: '2026-01-01T00:00:00+00:00', last_ts: '2026-01-01T00:00:00+00:00',
            relations: [], members_truncated: false },
  affected_assets: [{ hostname: 'HOST-A', zone: 'User_Endpoint', criticality: 'CRITICAL' }],
  techniques: ['T1059'],
  detection_summary: INCIDENTS.incidents[0].members,
  response: { incident_id: 'INC-0001', top_severity: 'CRITICAL', member_count: 1,
              driving_tactics: [], hosts: [], sections: { contain: [], eradicate: [], recover: [], validate: [] },
              unresolved_scenarios: [], note: '', honesty_note: 'resp note' },
  source_notes: { incident: 'inc note', response: 'resp note' },
  honesty_note: 'COMBINED report honesty note.',
  markdown: '# Post-Incident Report — INC-0001\n',
};

function mockApi() {
  vi.spyOn(api, 'apiGet').mockImplementation((url: string) => {
    if (url === '/api/incidents') return Promise.resolve(INCIDENTS as never);
    if (url === '/api/incident_response') return Promise.resolve(RESPONSES as never);
    if (url === '/api/incident_report/INC-0001') return Promise.resolve(REPORT as never);
    return Promise.reject(new Error(`unexpected url ${url}`));
  });
}

function setup() {
  return render(<MemoryRouter><Incidents /></MemoryRouter>);
}

describe('Incidents — report tab', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('opens the report drawer, renders sections, and downloads .md', async () => {
    mockApi();
    const dl = vi.spyOn(csv, 'downloadText').mockImplementation(() => {});
    setup();
    // expand the incident
    fireEvent.click(await screen.findByText('INC-0001'));
    // open the report drawer (the "View report" button → t returns the key)
    fireEvent.click(await screen.findByText('incidentReport.open'));
    // report content rendered (section labels are translation keys; honesty note is verbatim)
    expect(await screen.findByText('incidentReport.affectedAssets')).toBeInTheDocument();
    expect(await screen.findByText('COMBINED report honesty note.')).toBeInTheDocument();
    // download .md
    fireEvent.click(screen.getByText('incidentReport.download'));
    await waitFor(() => expect(dl).toHaveBeenCalledWith(
      'augur-incident-INC-0001.md', REPORT.markdown, 'text/markdown'));
  });
});
