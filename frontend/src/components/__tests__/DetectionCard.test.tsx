import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import DetectionCard, { type Detection } from '../DetectionCard';

vi.mock('../../lib/api', () => ({
  apiGet: vi.fn(() =>
    Promise.resolve({
      scenario_id: 'SCEN-WIN-001',
      label: 'Standard playbook — Credential Access',
      derived_from: { tactic: 'TA0006', tactic_name: 'Credential Access', severity: 'CRITICAL' },
      sections: {
        contain: ['Lock exposed accounts; revoke sessions.'],
        eradicate: ['Remove cred-dumping tools.'],
        recover: ['Force rotation.'],
        validate: [{ engine: 'splunk', query: 'index=win EventCode=4624' }],
      },
    })
  ),
  apiPost: vi.fn(() =>
    Promise.resolve({ ok: true, sink: 'preview', payload: { scenario_id: 'SCEN-WIN-001' } })
  ),
}));

const det: Detection = {
  scenario_id: 'SCEN-WIN-001', name: 'LSASS dump', severity: 'CRITICAL',
  proximity: 1, matched_steps: [{ step_id: 1, name: 'spawn', host: 'HR_User_PC' }],
  missing_steps: [], affected_hosts: ['HR_User_PC'], affected_zones: ['User_Endpoint'],
  hunting_queries: [],
};

const partial: Detection = {
  scenario_id: 'SCEN-WIN-002', name: 'Partial chain', severity: 'HIGH',
  proximity: 0.5,
  matched_steps: [{ step_id: 1, name: 'Beacon', host: 'PC1', timestamp: null }],
  missing_steps: [{ step_id: 2, name: 'LSASS access' }],
  affected_hosts: ['PC1'], affected_zones: ['User_Endpoint'], hunting_queries: [],
  stall: { kind: 'temporal', step_id: 2, host: 'PC1', delta_seconds: 300, window_seconds: 120 },
};

const rising: Detection = {
  ...det,
  momentum: { points: [0.25, 0.5, 0.75, 1.0], trend: 'rising', delta: 0.75, velocity: 0.25 },
};
const flat: Detection = {
  ...det,
  momentum: { points: [1, 1, 1], trend: 'flat', delta: 0, velocity: 0 },
};

describe('DetectionCard momentum', () => {
  it('renders sparkline + rising arrow + delta% when momentum is present', () => {
    render(<MemoryRouter><DetectionCard d={rising} onOpenCase={() => {}} /></MemoryRouter>);
    expect(screen.getByTestId('momentum-spark')).toBeInTheDocument();   // inline <svg>
    expect(screen.getByLabelText(/rising/i)).toBeInTheDocument();        // arrow aria-label
    expect(screen.getByText(/\+75%/)).toBeInTheDocument();               // Δ label
  });

  it('renders nothing momentum-related when the prop is absent (Alerts/Drill unaffected)', () => {
    render(<MemoryRouter><DetectionCard d={det} onOpenCase={() => {}} /></MemoryRouter>);
    expect(screen.queryByTestId('momentum-spark')).not.toBeInTheDocument();
  });

  it('renders the flat arrow for a flat trend', () => {
    render(<MemoryRouter><DetectionCard d={flat} onOpenCase={() => {}} /></MemoryRouter>);
    expect(screen.getByLabelText(/flat/i)).toBeInTheDocument();
  });
});

describe('DetectionCard', () => {
  it('renders name, scenario id, and proximity %', () => {
    render(<MemoryRouter><DetectionCard d={det} onOpenCase={() => {}} /></MemoryRouter>);
    expect(screen.getByText('LSASS dump')).toBeInTheDocument();
    expect(screen.getByText(/SCEN-WIN-001/)).toBeInTheDocument();
    expect(screen.getByText(/100%/)).toBeInTheDocument();
  });

  it('renders matched and missing steps when expanded', () => {
    render(<MemoryRouter><DetectionCard d={partial} onOpenCase={() => {}} /></MemoryRouter>);
    fireEvent.click(screen.getByRole('button', { name: /steps/i }));
    expect(screen.getByText(/Beacon/)).toBeInTheDocument();
    expect(screen.getByText(/LSASS access/)).toBeInTheDocument();
  });

  it('renders the stall ("why it stalled") line for a partial detection', () => {
    render(<MemoryRouter><DetectionCard d={partial} onOpenCase={() => {}} /></MemoryRouter>);
    expect(screen.getByText(/Why it stalled/i)).toBeInTheDocument();
  });

  it('calls onOpenCase when the case button is clicked', () => {
    let called = false;
    render(<MemoryRouter><DetectionCard d={det} onOpenCase={() => { called = true; }} /></MemoryRouter>);
    fireEvent.click(screen.getByRole('button', { name: /open case|view case/i }));
    expect(called).toBe(true);
  });
});

describe('DetectionCard playbook', () => {
  it('lazily fetches + renders the playbook panel when opened (opt-in via showPlaybook)', async () => {
    render(<MemoryRouter><DetectionCard d={det} onOpenCase={() => {}} showPlaybook /></MemoryRouter>);
    fireEvent.click(screen.getByRole('button', { name: /response playbook/i }));
    expect(await screen.findByText(/Lock exposed accounts/)).toBeInTheDocument();
    expect(screen.getByText(/Remove cred-dumping tools/)).toBeInTheDocument();
    expect(screen.getByText(/Force rotation/)).toBeInTheDocument();
    expect(screen.getByText(/index=win EventCode=4624/)).toBeInTheDocument();
    expect(screen.getByText(/Standard template/i)).toBeInTheDocument();
  });

  it('omits the playbook panel when showPlaybook is not set (Drill/Alerts unaffected)', () => {
    render(<MemoryRouter><DetectionCard d={det} onOpenCase={() => {}} /></MemoryRouter>);
    expect(screen.queryByRole('button', { name: /response playbook/i })).not.toBeInTheDocument();
  });

  it('Dispatch posts and shows the preview', async () => {
    render(<MemoryRouter><DetectionCard d={det} onOpenCase={() => {}} showPlaybook /></MemoryRouter>);
    fireEvent.click(screen.getByRole('button', { name: /response playbook/i }));
    fireEvent.click(await screen.findByRole('button', { name: /dispatch/i }));
    expect(await screen.findByText(/Would send this to your SIEM\/SOAR/i)).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toHaveTextContent('"scenario_id": "SCEN-WIN-001"');
  });
});
