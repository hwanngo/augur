import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Sessions, { type Session } from '../Sessions';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';

const server = setupServer();

const SESSIONS: Session[] = [
  {
    id: 'sess-001',
    created_at: '2024-01-01T10:00:00Z',
    last_seen: '2024-01-02T10:00:00Z',
    expires_at: '2024-02-01T10:00:00Z',
    current: true,
  },
  {
    id: 'sess-002',
    created_at: '2024-01-03T08:00:00Z',
    last_seen: '2024-01-03T09:00:00Z',
    expires_at: '2024-02-03T08:00:00Z',
    current: false,
  },
];

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });
  useAuthStore.setState({ user: 'alice', role: 'analyst', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
});
afterEach(() => {
  server.resetHandlers();
  server.close();
  vi.clearAllMocks();
});

function setup() {
  return render(
    <MemoryRouter>
      <Sessions />
    </MemoryRouter>
  );
}

describe('Sessions page', () => {
  it('lists sessions from the API', async () => {
    server.use(
      http.get('/api/auth/sessions', () => HttpResponse.json(SESSIONS))
    );

    setup();

    await waitFor(() => {
      // Current badge should be present
      expect(screen.getByText('Current')).toBeInTheDocument();
      // Two revoke buttons
      expect(screen.getAllByRole('button', { name: /revoke/i })).toHaveLength(2);
    });
  });

  it('opens confirm dialog when revoke is clicked', async () => {
    server.use(
      http.get('/api/auth/sessions', () => HttpResponse.json(SESSIONS))
    );

    setup();

    await waitFor(() => {
      expect(screen.getAllByRole('button', { name: /revoke/i })).toHaveLength(2);
    });

    fireEvent.click(screen.getAllByRole('button', { name: /revoke/i })[0]);

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });
  });

  it('calls DELETE on confirm and refreshes list', async () => {
    let deleteCalled = false;
    const remainingSessions = [SESSIONS[0]]; // only current remains

    server.use(
      http.get('/api/auth/sessions', () =>
        HttpResponse.json(deleteCalled ? remainingSessions : SESSIONS)
      ),
      http.delete('/api/auth/sessions/sess-002', () => {
        deleteCalled = true;
        return HttpResponse.json({ ok: true });
      })
    );

    setup();

    await waitFor(() => {
      expect(screen.getAllByRole('button', { name: /revoke/i })).toHaveLength(2);
    });

    // Click revoke on the non-current session (second row)
    fireEvent.click(screen.getAllByRole('button', { name: /revoke/i })[1]);

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    // Confirm
    fireEvent.click(screen.getByRole('button', { name: /^revoke$/i }));

    await waitFor(() => {
      expect(deleteCalled).toBe(true);
      // After refresh only 1 revoke button remains
      expect(screen.getAllByRole('button', { name: /revoke/i })).toHaveLength(1);
    });
  });

  it('shows empty state when no sessions', async () => {
    server.use(
      http.get('/api/auth/sessions', () => HttpResponse.json([]))
    );

    setup();

    await waitFor(() => {
      expect(screen.getByText(/no sessions/i)).toBeInTheDocument();
    });
  });
});
