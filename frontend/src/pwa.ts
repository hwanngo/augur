import { registerSW } from 'virtual:pwa-register';

/**
 * Register the service worker in autoUpdate mode (see vite.config.ts:
 * registerType: 'autoUpdate', skipWaiting: true, clientsClaim: true).
 *
 * A new build takes control immediately and the open page refreshes on the next
 * update check, so a stale cached bundle can never persist behind a dismissible
 * prompt (the prior 'prompt' flow caused exactly that). All live SOC data is
 * server-side (API responses are never cached), so an auto-refresh on a new
 * deploy refetches everything and loses no persisted state. Imported only from
 * main.tsx so the virtual module never reaches the test graph.
 */
export function setupPWA(): void {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) return;
  registerSW({
    onOfflineReady() {
      // App shell cached; live SOC data still requires a network connection.
    },
  });
}
