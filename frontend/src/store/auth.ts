import { create } from 'zustand';
import { apiGet, apiPost, apiPostForm, configureApi } from '../lib/api';

export type Role = 'viewer' | 'analyst' | 'admin';
export type AuthStatus = 'loading' | 'authed' | 'anon';

export interface AuthState {
  user: string | null;
  role: Role | null;
  csrf: string | null;
  status: AuthStatus;
  error: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  bootstrap: () => Promise<void>;
  clearAuth: () => void;
}

interface MeResponse {
  id: number;
  username: string;
  role: Role;
  csrf_token: string | null;
}

interface LoginResponse {
  user: string;
  role: Role;
  csrf_token: string;
}

let _navigate: ((path: string) => void) | null = null;

export function setNavigate(fn: (path: string) => void) {
  _navigate = fn;
}

const useAuthStore = create<AuthState>((set, get) => {
  const clearAuth = () => {
    set({ user: null, role: null, csrf: null, status: 'anon', error: null });
  };

  // Wire up the API unauthorised callback after store is created
  // (called lazily on first use)
  const ensureConfigured = () => {
    configureApi({
      onUnauthorized: () => {
        clearAuth();
        _navigate?.('/login');
      },
      getCsrf: () => get().csrf,
    });
  };

  return {
    user: null,
    role: null,
    csrf: null,
    status: 'loading',
    error: null,

    clearAuth,

    bootstrap: async () => {
      ensureConfigured();
      try {
        const me = await apiGet<MeResponse>('/api/auth/me');
        set({ user: me.username, role: me.role, csrf: me.csrf_token, status: 'authed', error: null });
      } catch {
        set({ user: null, role: null, csrf: null, status: 'anon', error: null });
      }
    },

    login: async (username, password) => {
      ensureConfigured();
      set({ error: null });
      const data = await apiPostForm<LoginResponse>('/api/auth/login', { username, password });
      set({ user: data.user, role: data.role, csrf: data.csrf_token, status: 'authed', error: null });
    },

    logout: async () => {
      try {
        await apiPost('/api/auth/logout');
      } catch {
        // ignore errors on logout
      }
      clearAuth();
      _navigate?.('/login');
    },
  };
});

export default useAuthStore;
