import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { act } from '@testing-library/react';

// We need to reset the module between tests to get a fresh store
// Instead, we import and reset state manually
import useAuthStore from '../auth';

const server = setupServer();

beforeEach(() => {
  server.listen({ onUnhandledFrame: 'error' });
  // Reset store to initial state
  useAuthStore.setState({ user: null, role: null, csrf: null, status: 'loading', error: null });
});

afterEach(() => {
  server.resetHandlers();
  server.close();
});

describe('auth store - login', () => {
  it('stores user, role, and csrf after successful login', async () => {
    server.use(
      http.post('/api/auth/login', () =>
        HttpResponse.json({ user: 'alice', role: 'analyst', csrf_token: 'tok123' })
      )
    );

    await act(async () => {
      await useAuthStore.getState().login('alice', 'secret');
    });

    const state = useAuthStore.getState();
    expect(state.user).toBe('alice');
    expect(state.role).toBe('analyst');
    expect(state.csrf).toBe('tok123');
    expect(state.status).toBe('authed');
  });

  it('throws on 401 invalid credentials', async () => {
    server.use(
      http.post('/api/auth/login', () =>
        HttpResponse.json({ detail: 'Invalid credentials' }, { status: 401 })
      )
    );

    await expect(useAuthStore.getState().login('alice', 'wrong')).rejects.toMatchObject({ status: 401 });
  });

  it('throws on 429 rate limited', async () => {
    server.use(
      http.post('/api/auth/login', () =>
        HttpResponse.json({ detail: 'Too many attempts' }, { status: 429 })
      )
    );

    await expect(useAuthStore.getState().login('alice', 'wrong')).rejects.toMatchObject({ status: 429 });
  });
});

describe('auth store - bootstrap', () => {
  it('sets status authed when /api/auth/me returns user', async () => {
    server.use(
      http.get('/api/auth/me', () =>
        HttpResponse.json({ id: 1, username: 'alice', role: 'admin' })
      )
    );

    await act(async () => {
      await useAuthStore.getState().bootstrap();
    });

    const state = useAuthStore.getState();
    expect(state.user).toBe('alice');
    expect(state.role).toBe('admin');
    expect(state.status).toBe('authed');
  });

  it('sets status anon when /api/auth/me returns 401', async () => {
    server.use(
      http.get('/api/auth/me', () => new HttpResponse(null, { status: 401 }))
    );

    await act(async () => {
      await useAuthStore.getState().bootstrap();
    });

    const state = useAuthStore.getState();
    expect(state.status).toBe('anon');
    expect(state.user).toBeNull();
  });
});

describe('auth store - logout', () => {
  it('clears state after logout', async () => {
    useAuthStore.setState({ user: 'alice', role: 'admin', csrf: 'tok', status: 'authed' });

    server.use(
      http.post('/api/auth/logout', () => new HttpResponse(null, { status: 200 }))
    );

    await act(async () => {
      await useAuthStore.getState().logout();
    });

    const state = useAuthStore.getState();
    expect(state.user).toBeNull();
    expect(state.csrf).toBeNull();
    expect(state.status).toBe('anon');
  });
});
