/**
 * Per-user, per-page saved-filter store backed by `localStorage`.
 *
 * Key shape: `augur.savedFilters.<scope>.<user|'_anon'>` where
 * `scope ∈ {'alerts','dashboard'}`. Values are the page's serialisable filter
 * record (defined per page). Ids are `crypto.randomUUID()` (browser-only;
 * never reaches the server, so no determinism concern).
 *
 * All functions are pure wrappers with try/catch: a private-mode / quota
 * failure is swallowed and the in-memory list is returned, never thrown.
 * A same-name save upserts (overwrites) to avoid duplicate clutter.
 */

export interface SavedFilter<F> {
  id: string;
  name: string;
  value: F;
  createdAt: string;
}

function keyFor(scope: string, user: string | null): string {
  return `augur.savedFilters.${scope}.${user ?? '_anon'}`;
}

export function loadSavedFilters<F>(scope: string, user: string | null): SavedFilter<F>[] {
  try {
    const raw = localStorage.getItem(keyFor(scope, user));
    if (!raw) return [];
    const parsed = JSON.parse(raw) as SavedFilter<F>[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persist<F>(scope: string, user: string | null, list: SavedFilter<F>[]): void {
  try {
    localStorage.setItem(keyFor(scope, user), JSON.stringify(list));
  } catch {
    /* private mode / quota — degrade silently to the in-memory list */
  }
}

export function saveSavedFilter<F>(
  scope: string,
  user: string | null,
  name: string,
  value: F
): SavedFilter<F>[] {
  const existing = loadSavedFilters<F>(scope, user);
  const idx = existing.findIndex((f) => f.name === name);
  let next: SavedFilter<F>[];
  if (idx >= 0) {
    next = existing.map((f, i) =>
      i === idx ? { ...f, value, createdAt: new Date().toISOString() } : f
    );
  } else {
    next = [
      ...existing,
      { id: crypto.randomUUID(), name, value, createdAt: new Date().toISOString() },
    ];
  }
  persist(scope, user, next);
  return next;
}

export function deleteSavedFilter<F>(
  scope: string,
  user: string | null,
  id: string
): SavedFilter<F>[] {
  const next = loadSavedFilters<F>(scope, user).filter((f) => f.id !== id);
  persist(scope, user, next);
  return next;
}
