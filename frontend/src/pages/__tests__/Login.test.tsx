import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Login from '../Login';
import useAuthStore from '../../store/auth';

const server = setupServer();

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });
  useAuthStore.setState({ user: null, role: null, csrf: null, status: 'anon', error: null });
});
afterEach(() => {
  server.resetHandlers();
  server.close();
});

const Dashboard = () => <div>Dashboard</div>;

function setup() {
  return render(
    <MemoryRouter initialEntries={['/login']}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('Login page', () => {
  it('submitting valid credentials navigates to dashboard', async () => {
    server.use(
      http.post('/api/auth/login', () =>
        HttpResponse.json({ user: 'alice', role: 'analyst', csrf_token: 'tok123' })
      )
    );

    const user = userEvent.setup();
    setup();

    await user.type(screen.getByLabelText(/username/i), 'alice');
    await user.type(screen.getByLabelText(/password/i), 'secret');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument();
    });
  });

  it('shows error message on 401', async () => {
    server.use(
      http.post('/api/auth/login', () =>
        HttpResponse.json({ detail: 'Invalid credentials' }, { status: 401 })
      )
    );

    const user = userEvent.setup();
    setup();

    await user.type(screen.getByLabelText(/username/i), 'alice');
    await user.type(screen.getByLabelText(/password/i), 'wrong');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText(/invalid username or password/i)).toBeInTheDocument();
    });
  });

  it('shows locked message on 429', async () => {
    server.use(
      http.post('/api/auth/login', () =>
        HttpResponse.json({ detail: 'Too many attempts' }, { status: 429 })
      )
    );

    const user = userEvent.setup();
    setup();

    await user.type(screen.getByLabelText(/username/i), 'alice');
    await user.type(screen.getByLabelText(/password/i), 'wrong');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText(/too many failed attempts/i)).toBeInTheDocument();
    });
  });
});
