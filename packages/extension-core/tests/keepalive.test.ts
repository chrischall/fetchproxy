import { describe, it, expect, vi } from 'vitest';
import { startKeepalive, KEEPALIVE_ALARM_NAME, KEEPALIVE_PERIOD_MINUTES } from '../src/keepalive.js';

/**
 * MV3 service workers idle out after ~30s without activity. WebSocket
 * traffic *does* reset the idle timer, but the moment the WS drops (or
 * just goes quiet for a beat), Chrome evicts the SW — and the
 * `setTimeout` reconnect we have queued doesn't fire from the dead worker.
 *
 * `chrome.alarms` is the documented MV3 keepalive: each alarm fire wakes
 * the SW from idle, runs the registered handler, and resets the timer.
 * `startKeepalive` registers ONE alarm at boot, and its handler calls
 * `ensureConnected()` — which is idempotent (no-op if the WS is already
 * open). On a dead WS, `ensureConnected` reconnects.
 */
describe('startKeepalive', () => {
  function makeAlarmsMock() {
    const handlers: Array<(alarm: { name: string }) => void> = [];
    const created: Array<{ name: string; opts: chrome.alarms.AlarmCreateInfo }> = [];
    const alarms = {
      create: vi.fn((name: string, opts: chrome.alarms.AlarmCreateInfo) => {
        created.push({ name, opts });
      }),
      onAlarm: {
        addListener: vi.fn((cb: (alarm: { name: string }) => void) => {
          handlers.push(cb);
        }),
      },
      fire: (name: string) => {
        for (const h of handlers) h({ name });
      },
    };
    return { alarms, created };
  }

  it('registers a single periodic alarm at boot', () => {
    const { alarms, created } = makeAlarmsMock();
    startKeepalive({
      alarms: alarms as unknown as typeof chrome.alarms,
      ensureConnected: () => {},
    });
    expect(created).toHaveLength(1);
    expect(created[0]!.name).toBe(KEEPALIVE_ALARM_NAME);
    expect(created[0]!.opts.periodInMinutes).toBe(KEEPALIVE_PERIOD_MINUTES);
  });

  it('uses a period under the MV3 idle-eviction window (< 30 seconds)', () => {
    // MV3 evicts service workers after ~30s of inactivity. A period of
    // exactly 30s leaves no headroom — pick something noticeably smaller.
    expect(KEEPALIVE_PERIOD_MINUTES).toBeLessThan(30 / 60);
    expect(KEEPALIVE_PERIOD_MINUTES).toBeGreaterThan(0);
  });

  it('calls ensureConnected when the alarm fires', () => {
    const { alarms } = makeAlarmsMock();
    const ensureConnected = vi.fn();
    startKeepalive({
      alarms: alarms as unknown as typeof chrome.alarms,
      ensureConnected,
    });
    expect(ensureConnected).not.toHaveBeenCalled();
    alarms.fire(KEEPALIVE_ALARM_NAME);
    expect(ensureConnected).toHaveBeenCalledTimes(1);
  });

  it('ignores alarms with other names', () => {
    const { alarms } = makeAlarmsMock();
    const ensureConnected = vi.fn();
    startKeepalive({
      alarms: alarms as unknown as typeof chrome.alarms,
      ensureConnected,
    });
    alarms.fire('some-other-alarm');
    expect(ensureConnected).not.toHaveBeenCalled();
  });

  it('survives ensureConnected throwing — the keepalive must not die', () => {
    const { alarms } = makeAlarmsMock();
    const ensureConnected = vi.fn(() => {
      throw new Error('connect blew up');
    });
    startKeepalive({
      alarms: alarms as unknown as typeof chrome.alarms,
      ensureConnected,
    });
    // First fire throws inside the handler, but should be caught.
    expect(() => alarms.fire(KEEPALIVE_ALARM_NAME)).not.toThrow();
    // Second fire should still call through.
    alarms.fire(KEEPALIVE_ALARM_NAME);
    expect(ensureConnected).toHaveBeenCalledTimes(2);
  });
});
