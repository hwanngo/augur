import { it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { useAlertSummary } from '../useAlertSummary';
import { configureApi } from '../api';

const server = setupServer();
beforeEach(() => { server.listen({ onUnhandledFrame: 'error' }); configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'tok' }); });
afterEach(() => { server.resetHandlers(); server.close(); });

it('reports openCount and seeds without a newCount on first poll', async () => {
  server.use(http.get('/api/alerts/summary', () =>
    HttpResponse.json({ open_count: 3, acknowledged_count: 0, max_alert_id: 5, latest_created_at: 'x' })));
  const { result } = renderHook(() => useAlertSummary(true));
  await waitFor(() => expect(result.current.openCount).toBe(3));
  expect(result.current.newCount).toBe(0);   // first poll only seeds
});

it('does not poll when disabled', async () => {
  let called = false;
  server.use(http.get('/api/alerts/summary', () => { called = true; return HttpResponse.json({ open_count: 0, max_alert_id: 0 }); }));
  renderHook(() => useAlertSummary(false));
  await new Promise((r) => setTimeout(r, 50));
  expect(called).toBe(false);
});
