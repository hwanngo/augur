import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import RequireRole from '../RequireRole';
import useAuthStore from '../../store/auth';

beforeEach(() => {
  useAuthStore.setState({ user: null, role: null, csrf: null, status: 'authed', error: null });
});

const AdminPage = () => <div>Admin Page</div>;

describe('RequireRole', () => {
  it('shows 403 when viewer tries to access admin route', () => {
    useAuthStore.setState({ role: 'viewer' });
    render(
      <RequireRole role="admin">
        <AdminPage />
      </RequireRole>
    );
    expect(screen.getByText('403')).toBeInTheDocument();
    expect(screen.queryByText('Admin Page')).not.toBeInTheDocument();
  });

  it('renders children when role matches', () => {
    useAuthStore.setState({ role: 'admin' });
    render(
      <RequireRole role="admin">
        <AdminPage />
      </RequireRole>
    );
    expect(screen.getByText('Admin Page')).toBeInTheDocument();
  });

  it('shows 403 when analyst tries admin route', () => {
    useAuthStore.setState({ role: 'analyst' });
    render(
      <RequireRole role="admin">
        <AdminPage />
      </RequireRole>
    );
    expect(screen.getByText('403')).toBeInTheDocument();
  });
});
