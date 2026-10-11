import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { setupServer } from 'msw/node';
import { http, HttpResponse, delay } from 'msw';
import { configureApi, apiGet, apiPost, ApiError } from '../api';

const server = setupServer();

beforeEach(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => { server.resetHandlers(); server.close(); });

describe('apiGet', () => {
  it('attaches X-CSRF-Token header when csrf is set', async () => {
    let receivedCsrf: string | null = null;

    server.use(
      http.get('/api/test', ({ request }) => {
        receivedCsrf = request.headers.get('X-CSRF-Token');
        return HttpResponse.json({ ok: true });
      })
    );

    configureApi({
      onUnauthorized: vi.fn(),
      getCsrf: () => 'test-csrf-token',
    });

    await apiGet('/api/test');
    expect(receivedCsrf).toBe('test-csrf-token');
  });

  it('returns parsed JSON on success', async () => {
    server.use(
      http.get('/api/data', () => HttpResponse.json({ value: 42 }))
    );
    configureApi({ onUnauthorized: vi.fn(), getCsrf: () => null });
    const result = await apiGet<{ value: number }>('/api/data');
    expect(result.value).toBe(42);
  });

  it('throws ApiError with status 404 on not found', async () => {
    server.use(
      http.get('/api/missing', () => new HttpResponse(null, { status: 404 }))
    );
    configureApi({ onUnauthorized: vi.fn(), getCsrf: () => null });
    await expect(apiGet('/api/missing')).rejects.toMatchObject({ status: 404 });
  });

  it('calls onUnauthorized and throws ApiError(401) on 401', async () => {
    const onUnauthorized = vi.fn();
    server.use(
      http.get('/api/protected', () => new HttpResponse(null, { status: 401 }))
    );
    configureApi({ onUnauthorized, getCsrf: () => null });

    await expect(apiGet('/api/protected')).rejects.toMatchObject({ status: 401 });
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });
});

describe('apiPost', () => {
  it('sends JSON body and CSRF header', async () => {
    let body: unknown = null;
    let csrf: string | null = null;

    server.use(
      http.post('/api/items', async ({ request }) => {
        body = await request.json();
        csrf = request.headers.get('X-CSRF-Token');
        return HttpResponse.json({ id: 1 }, { status: 201 });
      })
    );

    configureApi({ onUnauthorized: vi.fn(), getCsrf: () => 'my-csrf' });
    const result = await apiPost<{ id: number }>('/api/items', { name: 'test' });

    expect(result.id).toBe(1);
    expect(body).toEqual({ name: 'test' });
    expect(csrf).toBe('my-csrf');
  });
});

describe('request timeout', () => {
  it('aborts a hung request and throws a clean ApiError(0)', async () => {
    vi.useFakeTimers();
    server.use(
      http.get('/api/slow', async () => {
        // Never resolves within the timeout window.
        await delay('infinite');
        return HttpResponse.json({ ok: true });
      })
    );
    configureApi({ onUnauthorized: vi.fn(), getCsrf: () => null });

    const promise = apiGet('/api/slow');
    // Assert rejection before advancing so the rejection handler is attached.
    const assertion = expect(promise).rejects.toBeInstanceOf(ApiError);
    // Fast-forward past the 30s default timeout to trigger the AbortController.
    await vi.advanceTimersByTimeAsync(30_001);
    await assertion;
    await expect(promise).rejects.toMatchObject({ status: 0 });

    vi.useRealTimers();
  });
});
