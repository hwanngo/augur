import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import Dashboard from '../Dashboard';
import useAuthStore from '../../store/auth';
import { configureApi } from '../../lib/api';
import '../../i18n';

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return { ...actual, useNavigate: () => vi.fn() };
});

const server = setupServer();

beforeEach(() => {
  server.listen({ onUnhandledRequest: 'error' });   // every fetched endpoint must be mocked
  useAuthStore.setState({ user: 'alice', role: 'analyst', csrf: 'tok', status: 'authed' });
  configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' });
  localStorage.clear();
});
afterEach(() => {
  server.resetHandlers();
  server.close();
  localStorage.clear();
});

function mock(realData: boolean) {
  server.use(
    http.get('/api/health', () => HttpResponse.json({ status: 'ok', real_data: realData })),
    http.get('/api/detections', () => HttpResponse.json([])),
    http.get('/api/momentum', () => HttpResponse.json({ series: [] })),
  );
}

describe('Dashboard REAL DATASET banner', () => {
  it('shows the banner when /api/health real_data is true', async () => {
    mock(true);
    render(<MemoryRouter><Dashboard /></MemoryRouter>);
    await waitFor(() => expect(screen.getByText(/REAL DATASET/i)).toBeInTheDocument());
  });

  it('does NOT show the banner when real_data is false (default)', async () => {
    mock(false);
    render(<MemoryRouter><Dashboard /></MemoryRouter>);
    await waitFor(() => expect(screen.getByText(/Detections/i)).toBeInTheDocument());
    expect(screen.queryByText(/REAL DATASET/i)).toBeNull();
  });
});
