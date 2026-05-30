import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent, act, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import UsersPage, { type User } from '../Users';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';
import { ConfirmHost } from '../../components/useConfirm';
import { useConfirmStore } from '../../store/confirm';

const server = setupServer();

const USERS: User[] = [
  { id: 1, username: 'admin', role: 'admin', disabled: false, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z' },
  { id: 2, username: 'alice', role: 'analyst', disabled: false, created_at: '2024-01-02T00:00:00Z', updated_at: '2024-01-02T00:00:00Z' },
];

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });
  useAuthStore.setState({ user: 'admin', role: 'admin', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
});
afterEach(() => {
  server.resetHandlers();
  server.close();
  // Reset confirm store state between tests to avoid leakage
  useConfirmStore.setState({ open: false, options: null, resolve: null });
});

function setup() {
  return render(
    <MemoryRouter>
      <UsersPage />
      <ConfirmHost />
    </MemoryRouter>
  );
}

describe('Users page', () => {
  it('renders the user table with user rows', async () => {
    server.use(http.get('/api/users', () => HttpResponse.json(USERS)));
    setup();

    await waitFor(() => {
      expect(screen.getAllByText('admin').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('alice')).toBeInTheDocument();
    });
  });

  it('shows delete confirmation dialog when delete button clicked', async () => {
    server.use(http.get('/api/users', () => HttpResponse.json(USERS)));
    setup();

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument();
    });

    // Click delete button for a user
    const deleteButtons = screen.getAllByRole('button', { name: /delete/i });
    fireEvent.click(deleteButtons[0]);

    // Dialog should appear (via ConfirmHost)
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });
  });

  it('shows create user dialog when New User button clicked', async () => {
    server.use(http.get('/api/users', () => HttpResponse.json(USERS)));
    setup();

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /create user/i }));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.getByText('Create User')).toBeInTheDocument();
    });
  });

  it('creates a user and refreshes list', async () => {
    let createCalled = false;
    const updatedUsers = [...USERS, { id: 3, username: 'bob', role: 'viewer', disabled: false, created_at: '2024-01-03T00:00:00Z', updated_at: '2024-01-03T00:00:00Z' }];

    server.use(
      http.get('/api/users', () => HttpResponse.json(createCalled ? updatedUsers : USERS)),
      http.post('/api/users', () => { createCalled = true; return HttpResponse.json({ id: 3 }, { status: 201 }); })
    );

    setup();

    await waitFor(() => {
      expect(screen.getAllByText('admin').length).toBeGreaterThanOrEqual(1);
    });

    // Open create dialog
    fireEvent.click(screen.getByRole('button', { name: /create user/i }));

    await waitFor(() => {
      expect(screen.getByText('Create User')).toBeInTheDocument();
    });

    // Fill in form
    const usernameInput = screen.getByPlaceholderText('username');
    const passwordInput = screen.getByPlaceholderText('min 8 characters');
    fireEvent.change(usernameInput, { target: { value: 'bob' } });
    fireEvent.change(passwordInput, { target: { value: 'password123' } });

    // Click Create
    fireEvent.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => {
      expect(screen.getByText('bob')).toBeInTheDocument();
    });
  });

  it('deletes a user after confirming the dialog', async () => {
    let deleteCalled = false;
    const remainingUsers = [USERS[0]];

    server.use(
      http.get('/api/users', () => HttpResponse.json(deleteCalled ? remainingUsers : USERS)),
      http.delete('/api/users/2', () => { deleteCalled = true; return HttpResponse.json({ ok: true }); })
    );

    setup();

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument();
    });

    // Click delete button for alice (second user)
    const deleteButtons = screen.getAllByRole('button', { name: /delete/i });
    fireEvent.click(deleteButtons[1]);

    // Confirm dialog should appear
    const dialog = await screen.findByRole('dialog');
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: /delete/i }));
    });

    await waitFor(() => {
      expect(deleteCalled).toBe(true);
      expect(screen.queryByText('alice')).not.toBeInTheDocument();
    });
  });
});
