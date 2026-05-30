import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Incidents from './Incidents';
import * as api from '../lib/api';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k),
  }),
}));

const RESP = {
  incidents: [
    {
      incident_id: 'INC-0001', size: 2,
      members: [
        { scenario_id: 'SCEN-WIN-001', name: 'Recon', severity: 'HIGH', proximity: 1.0,
          affected_hosts: ['HOST-A'], latest_ts: '2026-01-01T10:00:00+00:00' },
        { scenario_id: 'SCEN-WIN-002', name: 'Exec', severity: 'CRITICAL', proximity: 0.5,
          affected_hosts: ['HOST-A'], latest_ts: '2026-01-01T10:05:00+00:00' },
      ],
      members_truncated: false,
      hosts: [{ hostname: 'HOST-A', zone: 'User_Endpoint', criticality: 'CRITICAL' }],
      techniques: ['T1059', 'T1003'],
      first_ts: '2026-01-01T10:00:00+00:00', last_ts: '2026-01-01T10:05:00+00:00',
      top_severity: 'CRITICAL', max_proximity: 1.0, score: 5.0,
      relations: ['shared_host', 'shared_technique'],
      honesty_note: 'An incident is a deterministic CORRELATION over THIS corpus …',
    },
    {
      incident_id: 'INC-0002', size: 1,
      members: [
        { scenario_id: 'SCEN-LNX-001', name: 'Cred', severity: 'LOW', proximity: 0.5,
          affected_hosts: ['HOST-B'], latest_ts: '2026-02-01T10:00:00+00:00' },
      ],
      members_truncated: false,
      hosts: [{ hostname: 'HOST-B', zone: 'User_Endpoint', criticality: 'LOW' }],
      techniques: ['T1110'],
      first_ts: '2026-02-01T10:00:00+00:00', last_ts: '2026-02-01T10:00:00+00:00',
      top_severity: 'LOW', max_proximity: 0.5, score: 0.5, relations: [],
      honesty_note: 'An incident is a deterministic CORRELATION over THIS corpus …',
    },
  ],
  rollup: {
    incidents: 2, clustered_detections: 2, singletons: 1, largest_incident_size: 2,
    detections_total: 3, truncated: false,
    honesty_note: 'An incident is a deterministic CORRELATION over THIS corpus …',
  },
};

const RESP_RESP = {
  responses: [
    {
      incident_id: 'INC-0001', top_severity: 'CRITICAL', member_count: 2,
      driving_tactics: [{ tactic: 'TA0001', tactic_name: 'Initial Access' }],
      hosts: [{ hostname: 'HOST-A', zone: 'User_Endpoint', criticality: 'CRITICAL' }],
      sections: {
        contain: [{ action: 'Escalate: page on-call IR and open a major-incident bridge.',
                    from_scenarios: ['SCEN-WIN-001', 'SCEN-WIN-002'] }],
        eradicate: [{ action: 'Remove dropped payload; close exposed service.',
                      from_scenarios: ['SCEN-WIN-001'] }],
        recover: [{ action: 'Restore host; patch the access vector.',
                    from_scenarios: ['SCEN-WIN-001'] }],
        validate: [{ engine: 'splunk', query: 'index=win foo', query_path: 'a/b.spl',
                     from_scenarios: ['SCEN-WIN-001'] }],
      },
      unresolved_scenarios: [], note: '',
      honesty_note: 'A consolidated response plan is the UNION of STANDARD …',
    },
    {
      incident_id: 'INC-0002', top_severity: 'LOW', member_count: 1,
      driving_tactics: [{ tactic: 'TA0006', tactic_name: 'Credential Access' }],
      hosts: [{ hostname: 'HOST-B', zone: 'User_Endpoint', criticality: 'LOW' }],
      sections: {
        contain: [{ action: 'Lock exposed accounts; revoke sessions.', from_scenarios: ['SCEN-LNX-001'] }],
        eradicate: [], recover: [], validate: [],
      },
      unresolved_scenarios: [], note: '',
      honesty_note: 'A consolidated response plan is the UNION of STANDARD …',
    },
  ],
  honesty_note: 'A consolidated response plan is the UNION of STANDARD …',
};

function mockApi() {
  return vi.spyOn(api, 'apiGet').mockImplementation((url: string) =>
    Promise.resolve((url === '/api/incident_response' ? RESP_RESP : RESP) as never));
}

function renderAt(path = '/incidents') {
  return render(<MemoryRouter initialEntries={[path]}><Incidents /></MemoryRouter>);
}

describe('Incidents — clustering page', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('loads on mount and renders the rollup band + at least one incident card', async () => {
    const spy = mockApi();
    renderAt();
    await waitFor(() => expect(screen.getByText('INC-0001')).toBeInTheDocument());
    expect(spy).toHaveBeenCalledWith('/api/incidents');
    expect(spy).toHaveBeenCalledWith('/api/incident_response');
    expect(screen.getByText('INC-0002')).toBeInTheDocument();
  });

  it('renders the persistent honesty panel (verbatim note)', async () => {
    mockApi();
    renderAt();
    await waitFor(() =>
      expect(screen.getByText(/deterministic CORRELATION over THIS corpus/)).toBeInTheDocument());
  });

  it('shows the relations badges for a grouped incident', async () => {
    mockApi();
    renderAt();
    await waitFor(() => expect(screen.getByText('INC-0001')).toBeInTheDocument());
    expect(screen.getByText('incidents.relation.shared_host')).toBeInTheDocument();
    expect(screen.getByText('incidents.relation.shared_technique')).toBeInTheDocument();
  });

  it('expanding an incident reveals its member detections', async () => {
    mockApi();
    renderAt();
    await waitFor(() => expect(screen.getByText('INC-0001')).toBeInTheDocument());
    expect(screen.queryByText('SCEN-WIN-001')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /incidents.expand.*INC-0001/ }));
    await waitFor(() => expect(screen.getByText('SCEN-WIN-001')).toBeInTheDocument());
    expect(screen.getByText('SCEN-WIN-002')).toBeInTheDocument();
  });

  it('?incident=INC-0001 deep-link pre-expands that incident on mount', async () => {
    mockApi();
    renderAt('/incidents?incident=INC-0001');
    await waitFor(() => expect(screen.getByText('SCEN-WIN-001')).toBeInTheDocument());
  });

  it('opens the Response drawer and renders the four sections + provenance + honesty', async () => {
    mockApi();
    renderAt('/incidents?incident=INC-0001');
    // expand, then click "View response"
    await waitFor(() => expect(screen.getByText('SCEN-WIN-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'incidentResponse.open' }));
    // drawer shows the escalate contain action and its provenance chips
    await waitFor(() =>
      expect(screen.getByText(/Escalate: page on-call IR/)).toBeInTheDocument());
    expect(screen.getByText('incidentResponse.section.contain')).toBeInTheDocument();
    expect(screen.getByText('incidentResponse.section.eradicate')).toBeInTheDocument();
    expect(screen.getByText('incidentResponse.section.recover')).toBeInTheDocument();
    expect(screen.getByText('incidentResponse.section.validate')).toBeInTheDocument();
    // provenance chips for the escalate action list both members (each member may appear in
    // multiple sections' provenance, so assert at-least-one occurrence within the drawer)
    const drawer = screen.getByRole('dialog');
    expect(within(drawer).getAllByText('SCEN-WIN-001').length).toBeGreaterThan(0);
    expect(within(drawer).getAllByText('SCEN-WIN-002').length).toBeGreaterThan(0);
    // verbatim honesty note from the payload
    expect(screen.getByText(/UNION of STANDARD/)).toBeInTheDocument();
  });

  it('Response drawer offers a CSV export of the flattened plan', async () => {
    mockApi();
    renderAt('/incidents?incident=INC-0001');
    await waitFor(() => expect(screen.getByText('SCEN-WIN-001')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'incidentResponse.open' }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'incidentResponse.csv.export' })).toBeInTheDocument());
  });
});
