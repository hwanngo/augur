import { useEffect, useMemo, useState } from 'react';

/**
 * Client-side pagination over an in-memory list.
 *
 * Resets to page 1 whenever the result count changes (i.e. a filter/search
 * narrowed or widened the set), so the user never lands on a now-empty page.
 */
export function usePagination<T>(items: T[], pageSize: number) {
  const [page, setPage] = useState(1);
  const total = items.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  // A changed result count means the upstream filter changed → start over.
  useEffect(() => { setPage(1); }, [total, pageSize]);

  const pageItems = useMemo(
    () => items.slice((page - 1) * pageSize, page * pageSize),
    [items, page, pageSize],
  );

  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return { page, setPage, pageCount, pageItems, total, start, end };
}
