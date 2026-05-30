import { useEffect, useRef, useState } from 'react';
import { apiGet } from './api';

export interface AlertSummary {
  open_count: number;
  acknowledged_count?: number;
  resolved_count?: number;
  in_progress_count?: number;
  closed_count?: number;
  unassigned_count?: number;
  by_status?: Record<string, number>;
  max_alert_id: number;
  latest_created_at?: string;
}

const POLL_MS = 15000;

export function useAlertSummary(enabled: boolean) {
  const [openCount, setOpenCount] = useState(0);
  const [newCount, setNewCount] = useState(0);
  const prevMaxId = useRef<number | null>(null);
  const prevOpen = useRef<number>(0);

  useEffect(() => {
    if (!enabled) return;
    let active = true;

    const poll = async () => {
      if (typeof document !== 'undefined' && document.hidden) return;
      try {
        const s = await apiGet<AlertSummary>('/api/alerts/summary');
        if (!active) return;
        setOpenCount(s.open_count);
        if (prevMaxId.current === null) {
          prevMaxId.current = s.max_alert_id;        // seed: no toast on first load
        } else if (s.max_alert_id > prevMaxId.current || s.open_count > prevOpen.current) {
          setNewCount(s.max_alert_id - prevMaxId.current);
          prevMaxId.current = s.max_alert_id;
        }
        prevOpen.current = s.open_count;
      } catch {
        /* swallow: viewer 403 / transient / unauth must never crash the shell */
      }
    };

    void poll();
    const id = setInterval(() => void poll(), POLL_MS);
    return () => { active = false; clearInterval(id); };
  }, [enabled]);

  const clearNew = () => setNewCount(0);
  return { openCount, newCount, clearNew };
}
