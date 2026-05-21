/**
 * MV3 service-worker keepalive for fetchproxy.
 *
 * Chrome MV3 idles service workers after ~30 seconds without activity.
 * WebSocket traffic *does* reset that timer in Chrome 116+, but only
 * while the WS is actually receiving frames — if the host has nothing
 * to say for half a minute, or if the WS goes silent because we
 * reconnected and the host's first message is still in flight, the SW
 * gets evicted and any pending `setTimeout` (our reconnect backoff)
 * vanishes with it.
 *
 * `chrome.alarms` is the documented MV3 escape hatch: a registered
 * alarm fires regardless of SW state, and the firing wakes the worker
 * if it had been evicted. We register one periodic alarm at boot, and
 * the handler re-runs the connect() path — which is idempotent (no-op
 * when the WS is open, reconnect when it isn't).
 *
 * The handler is wrapped in try/catch so an exception in connect()
 * can't break the alarm subscription; the next tick still fires.
 *
 * Period: 0.4 minutes = 24 seconds, comfortably below the ~30s idle
 * window. Chrome clamps `periodInMinutes` to 0.5 (30s) in stable; we
 * still pass 0.4 so that if Chrome ever loosens the clamp we get the
 * smaller value, and if not the clamp leaves us right at the edge —
 * which is fine because each alarm fire reactivates the SW.
 */

export const KEEPALIVE_ALARM_NAME = 'fetchproxy-keepalive';
export const KEEPALIVE_PERIOD_MINUTES = 0.4;

export interface KeepaliveDeps {
  /** chrome.alarms — the typed `chrome.alarms` global in production. */
  alarms: typeof chrome.alarms;
  /**
   * Idempotent reconnect entry point. Called on every alarm fire. The
   * production wiring passes `connect` from background.ts, which
   * short-circuits when the WS is already connecting or open.
   */
  ensureConnected: () => void;
}

/**
 * Register the keepalive alarm and its handler. Call once at SW boot.
 * Idempotent w.r.t. `chrome.alarms.create` — Chrome treats a second
 * `create` with the same name as a replace, so this is safe across
 * SW restarts.
 */
export function startKeepalive(deps: KeepaliveDeps): void {
  deps.alarms.create(KEEPALIVE_ALARM_NAME, {
    periodInMinutes: KEEPALIVE_PERIOD_MINUTES,
  });
  deps.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name !== KEEPALIVE_ALARM_NAME) return;
    try {
      deps.ensureConnected();
    } catch (e) {
      // Don't let a thrown ensureConnected break the subscription —
      // the next alarm should still fire.
      console.error('[fetchproxy] keepalive ensureConnected:', e);
    }
  });
}
