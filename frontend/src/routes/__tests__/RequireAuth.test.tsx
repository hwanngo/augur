import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import RequireAuth from '../RequireAuth';
import useAuthStore from '../../store/auth';

beforeEach(() => {
  useAuthStore.setState({ user: null, role: null, csrf: null, status: 'loading', error: null });
});

const Protected = () => <div>Protected Content</div>;
const Login = () => <div>Login Page</div>;

function setup(initialPath = '/dashboard') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/dashboard"
          element={
            <RequireAuth>
              <Protected />
            </RequireAuth>
          }
        />
      </Routes>
    </MemoryRouter>
  );
}

describe('RequireAuth', () => {
  it('shows loading spinner when status is loading', () => {
    useAuthStore.setState({ status: 'loading' });
    setup();
    // Should not show protected content, should show a spinner (no text)
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    expect(screen.queryByText('Login Page')).not.toBeInTheDocument();
  });

  it('redirects to /login when anon', () => {
    useAuthStore.setState({ status: 'anon' });
    setup();
    expect(screen.getByText('Login Page')).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('renders children when authed', () => {
    useAuthStore.setState({ status: 'authed', user: 'alice', role: 'viewer', csrf: 'tok' });
    setup();
    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });
});
