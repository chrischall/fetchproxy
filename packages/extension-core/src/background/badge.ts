/**
 * Toolbar action badge state, moved verbatim out of `background.ts`.
 *
 * The three module-level `let`s stay private to this file on purpose:
 * `syncBadge` consults `pairPendingActive` first and `flashActivity` bails
 * while it is set, so the pending-pair badge always wins. Splitting that
 * state across modules would break the priority silently.
 *
 * Reaches chrome through the same `globalThis` cast the original used, so
 * this module needs no chrome declaration at all.
 */

// -------------------------------------------------------------------
// 0.4.2: action badge + auto-popup attempt
//
// The pair flow used to surface only when the user manually opened
// the extension popup — easy to miss. Now we paint a red "!" badge
// on the toolbar icon whenever a pending pair is queued, and
// (best-effort) try `chrome.action.openPopup()` to surface it
// without the user having to click. The badge clears once the
// pending pair is removed (approved, dismissed, or trust landed).
//
// `openPopup()` is restricted: generally requires a recent user
// gesture and only available in Chrome 127+ from MV3 background.
// We swallow exceptions so unsupported environments still get the
// badge — the badge alone is enough to make the pending pair
// visible.
// -------------------------------------------------------------------

const BADGE_PAIR_PENDING_TEXT = '!';
const BADGE_PAIR_PENDING_COLOR = '#dc2626';
const BADGE_CONNECTED_COLOR = '#22c55e';
const BADGE_ACTIVE_COLOR = '#15803d';
const BADGE_DISCONNECTED_COLOR = '#f59e0b';

type ConnectionStatus = 'connected' | 'disconnected' | 'error';
let currentConnectionStatus: ConnectionStatus = 'disconnected';
let pairPendingActive = false;
let activityTimer: ReturnType<typeof setTimeout> | null = null;

function getAction(): {
  setBadgeText: (d: { text: string }) => Promise<void> | void;
  setBadgeBackgroundColor?: (d: { color: string }) => Promise<void> | void;
  openPopup?: () => Promise<void>;
} | null {
  const c = (globalThis as { chrome?: { action?: unknown } }).chrome;
  const action = c?.action as {
    setBadgeText: (d: { text: string }) => Promise<void> | void;
    setBadgeBackgroundColor?: (d: { color: string }) => Promise<void> | void;
    openPopup?: () => Promise<void>;
  } | undefined;
  if (!action || typeof action.setBadgeText !== 'function') return null;
  return action;
}

function setBadge(text: string, color: string): void {
  const action = getAction();
  if (!action) return;
  try {
    void action.setBadgeText({ text });
    if (typeof action.setBadgeBackgroundColor === 'function') {
      void action.setBadgeBackgroundColor({ color });
    }
  } catch (e) {
    console.warn('[fetchproxy] setBadge:', e);
  }
}

export function syncBadge(): void {
  if (pairPendingActive) {
    setBadge(BADGE_PAIR_PENDING_TEXT, BADGE_PAIR_PENDING_COLOR);
    return;
  }
  switch (currentConnectionStatus) {
    case 'connected':
      setBadge(' ', BADGE_CONNECTED_COLOR);
      break;
    case 'disconnected':
      setBadge(' ', BADGE_DISCONNECTED_COLOR);
      break;
    case 'error':
      setBadge(' ', BADGE_PAIR_PENDING_COLOR);
      break;
  }
}

export function setConnectionStatus(status: ConnectionStatus): void {
  currentConnectionStatus = status;
  syncBadge();
}

export function flashActivity(): void {
  if (pairPendingActive) return;
  if (activityTimer) clearTimeout(activityTimer);
  setBadge(' ', BADGE_ACTIVE_COLOR);
  activityTimer = setTimeout(() => {
    activityTimer = null;
    syncBadge();
  }, 300);
}

export function setPairPendingBadge(): void {
  pairPendingActive = true;
  setBadge(BADGE_PAIR_PENDING_TEXT, BADGE_PAIR_PENDING_COLOR);
  const action = getAction();
  if (!action) return;
  // Best-effort auto-open. Chrome 127+ MV3 allows openPopup() from
  // background in some contexts; otherwise it throws either sync
  // or async — both swallowed so the badge alone still wins.
  if (typeof action.openPopup === 'function') {
    try {
      void action.openPopup().catch(() => {
        /* expected in older Chrome / no-gesture contexts */
      });
    } catch {
      /* sync throw — older Chrome */
    }
  }
}

export function clearPairPendingBadge(): void {
  pairPendingActive = false;
  syncBadge();
}
