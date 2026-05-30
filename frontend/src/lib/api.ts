/**
 * Augur API wrapper
 * - credentials: 'include' (session cookie)
 * - X-CSRF-Token header on mutations
 * - 401 → clears auth store + redirects to /login
 */

let _onUnauthorized: (() => void) | null = null;
let _getCsrf: (() => string | null) | null = null;

export function configureApi(opts: {
  onUnauthorized: () => void;
  getCsrf: () => string | null;
}) {
  _onUnauthorized = opts.onUnauthorized;
  _getCsrf = opts.getCsrf;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** Default request timeout (ms). A slow/hung backend should not wedge the UI. */
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * fetch() with a default abort-timeout. A timeout (or an aborted request)
 * surfaces as a normal Error (status 0) that callers already handle via the
 * existing catch paths. Honors an optionally caller-supplied AbortSignal.
 */
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs = DEFAULT_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);

  // Chain any caller-supplied signal into our controller (and clean the
  // listener up afterwards so it doesn't leak onto a long-lived shared signal).
  const external = init.signal;
  const onExternalAbort = () => controller.abort();
  if (external) {
    if (external.aborted) controller.abort();
    else external.addEventListener('abort', onExternalAbort, { once: true });
  }

  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (err) {
    // Detect aborts by name, not `instanceof DOMException`: the abort error can be a DOMException
    // from a different realm (e.g. Node's fetch under jsdom in tests), where instanceof fails. The
    // name is 'AbortError' in every environment, including real browsers.
    if ((err as { name?: string } | null)?.name === 'AbortError') {
      // Only OUR timeout maps to a timeout error; a caller-initiated abort
      // propagates unchanged so it isn't mislabeled as a timeout.
      if (timedOut) throw new ApiError(0, `Request timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
    external?.removeEventListener('abort', onExternalAbort);
  }
}

async function apiFetch<T>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const csrf = _getCsrf?.();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };
  if (csrf) {
    headers['X-CSRF-Token'] = csrf;
  }

  const res = await fetchWithTimeout(url, {
    credentials: 'include',
    ...options,
    headers,
  });

  if (res.status === 401) {
    _onUnauthorized?.();
    throw new ApiError(401, 'Unauthorized');
  }

  if (!res.ok) {
    let message = res.statusText;
    try {
      const body = await res.json() as { detail?: string };
      message = body.detail ?? message;
    } catch {
      // ignore
    }
    throw new ApiError(res.status, message);
  }

  // Handle 204 No Content
  if (res.status === 204) {
    return undefined as T;
  }

  return res.json() as Promise<T>;
}

export const apiGet = <T>(url: string) =>
  apiFetch<T>(url, { method: 'GET' });

export const apiPost = <T>(url: string, body?: unknown) =>
  apiFetch<T>(url, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined });

export const apiPostForm = <T>(url: string, data: Record<string, string>) => {
  const csrf = _getCsrf?.();
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (csrf) {
    headers['X-CSRF-Token'] = csrf;
  }
  const body = Object.entries(data)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

  return fetchWithTimeout(url, {
    method: 'POST',
    credentials: 'include',
    headers,
    body,
  }).then(async (res) => {
    if (res.status === 401) {
      _onUnauthorized?.();
      throw new ApiError(401, 'Unauthorized');
    }
    if (!res.ok) {
      let message = res.statusText;
      try {
        const body = await res.json() as { detail?: string };
        message = body.detail ?? message;
      } catch {
        // ignore
      }
      throw new ApiError(res.status, message);
    }
    return res.json() as Promise<T>;
  });
};

export const apiPatch = <T>(url: string, body: unknown) =>
  apiFetch<T>(url, { method: 'PATCH', body: JSON.stringify(body) });

export const apiDelete = <T>(url: string) =>
  apiFetch<T>(url, { method: 'DELETE' });
