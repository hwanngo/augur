import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Audit, { type AuditEntry } from '../Audit';
import RequireRole from '../../routes/RequireRole';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';

const server = setupServer();

const ENTRIES: AuditEntry[] = [
  { id: 1, ts: '2024-01-01T10:00:00Z', username: 'alice', event: 'login', ip: '192.168.1.1', detail: 'Login success' },
  { id: 2, ts: '2024-01-02T09:00:00Z', username: 'bob', event: 'login_failed', ip: '10.0.0.5', detail: 'Bad password' },
  { id: 3, ts: '2024-01-03T08:00:00Z', username: 'alice', event: 'user_created', ip: '192.168.1.1', detail: 'Created user bob' },
];

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });
  useAuthStore.setState({ user: 'admin', role: 'admin', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
});
afterEach(() => {
  server.resetHandlers();
  server.close();
});

function setup() {
  return render(
    <MemoryRouter>
      <Audit />
    </MemoryRouter>
  );
}

describe('Audit page', () => {
  it('renders audit rows from a mocked response', async () => {
    server.use(
      http.get('/api/audit', () => HttpResponse.json(ENTRIES))
    );

    setup();

    await waitFor(() => {
      expect(screen.getAllByText('alice').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('bob')).toBeInTheDocument();
      expect(screen.getByText('login')).toBeInTheDocument();
      expect(screen.getByText('login_failed')).toBeInTheDocument();
    });
  });

  it('changes limit and re-fetches on selection change', async () => {
    const fetchedLimits: string[] = [];

    server.use(
      http.get('/api/audit', ({ request }) => {
        const url = new URL(request.url);
        fetchedLimits.push(url.searchParams.get('limit') ?? '');
        return HttpResponse.json(ENTRIES);
      })
    );

    setup();

    await waitFor(() => {
      expect(screen.getAllByText('alice').length).toBeGreaterThanOrEqual(1);
    });

    const trigger = screen.getByRole('combobox');
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('option', { name: '500' }));

    await waitFor(() => {
      expect(fetchedLimits).toContain('500');
    });
  });

  it('is gated to admin via RequireRole', () => {
    useAuthStore.setState({ user: 'viewer', role: 'viewer', csrf: 'tok', status: 'authed' });

    render(
      <MemoryRouter>
        <RequireRole role="admin">
          <Audit />
        </RequireRole>
      </MemoryRouter>
    );

    expect(screen.getByText('403')).toBeInTheDocument();
  });

  it('shows empty state when no entries', async () => {
    server.use(
      http.get('/api/audit', () => HttpResponse.json([]))
    );

    setup();

    await waitFor(() => {
      expect(screen.getByText(/no audit events/i)).toBeInTheDocument();
    });
  });

  it('shows error on fetch failure', async () => {
    server.use(
      http.get('/api/audit', () => HttpResponse.json({ detail: 'Forbidden' }, { status: 403 }))
    );

    setup();

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });
});
