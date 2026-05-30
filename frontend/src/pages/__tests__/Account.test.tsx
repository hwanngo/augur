import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Account from '../Account';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';
import Toaster from '../../components/Toaster';
import { useToastStore } from '../../store/toast';

const server = setupServer();

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });
  useAuthStore.setState({ user: 'alice', role: 'analyst', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
  act(() => useToastStore.setState({ show: false, message: '', status: 'success' }));
});
afterEach(() => {
  server.resetHandlers();
  server.close();
  act(() => useToastStore.setState({ show: false, message: '', status: 'success' }));
});

function setup() {
  return render(
    <MemoryRouter>
      <Account />
      <Toaster />
    </MemoryRouter>
  );
}

function fillForm(current: string, newPw: string, confirm: string) {
  fireEvent.change(screen.getByPlaceholderText(/current password/i), { target: { value: current } });
  fireEvent.change(screen.getByPlaceholderText(/min 12 characters/i), { target: { value: newPw } });
  fireEvent.change(screen.getByPlaceholderText(/repeat new password/i), { target: { value: confirm } });
}

describe('Account page', () => {
  it('renders the current user name and role', () => {
    setup();
    expect(screen.getByText('alice')).toBeInTheDocument();
    expect(screen.getByText('analyst')).toBeInTheDocument();
  });

  it('submit button is disabled when form is invalid', () => {
    setup();
    const btn = screen.getByRole('button', { name: /update password/i });
    expect(btn).toBeDisabled();
  });

  it('shows validation error when new password is too short', () => {
    setup();
    fillForm('old', 'short', 'short');
    expect(screen.getByText(/minimum 12/i)).toBeInTheDocument();
  });

  it('shows error when new password matches current', () => {
    setup();
    fillForm('samepassword123', 'samepassword123', 'samepassword123');
    expect(screen.getByText(/must differ/i)).toBeInTheDocument();
  });

  it('shows error when confirm does not match', () => {
    setup();
    fillForm('oldpassword123', 'newpassword456!', 'differentpassword');
    expect(screen.getByText(/do not match/i)).toBeInTheDocument();
  });

  it('submits change-password and shows success toast', async () => {
    server.use(
      http.post('/api/auth/change-password', () => HttpResponse.json({ ok: true }))
    );

    setup();
    fillForm('oldpassword123!', 'newpassword456!X', 'newpassword456!X');

    const btn = screen.getByRole('button', { name: /update password/i });
    expect(btn).not.toBeDisabled();
    fireEvent.click(btn);

    await waitFor(() => {
      expect(screen.getByText(/password updated/i)).toBeInTheDocument();
    });
  });

  it('shows wrong current password error on 401', async () => {
    server.use(
      http.post('/api/auth/change-password', () => HttpResponse.json({ detail: 'Wrong' }, { status: 401 }))
    );

    setup();
    fillForm('wrongpassword12!', 'newpassword456!X', 'newpassword456!X');
    fireEvent.click(screen.getByRole('button', { name: /update password/i }));

    await waitFor(() => {
      expect(screen.getByText(/current password is incorrect/i)).toBeInTheDocument();
    });
  });

  it('shows policy error on 422', async () => {
    server.use(
      http.post('/api/auth/change-password', () => HttpResponse.json({ detail: 'Weak' }, { status: 422 }))
    );

    setup();
    fillForm('oldpassword123!', 'newpassword456!X', 'newpassword456!X');
    fireEvent.click(screen.getByRole('button', { name: /update password/i }));

    await waitFor(() => {
      expect(screen.getByText(/policy/i)).toBeInTheDocument();
    });
  });
});
