/**
 * Popup UI for the Transporter extension. Three modes:
 *
 *   - pending-pair: a new MCP is asking to pair. Show the SAS pair code
 *     prominently with Approve / Cancel buttons (Cancel default-focused).
 *   - status: no pending pair; list trusted MCPs (serverName → domain).
 *   - empty: no pending, no trusted; show a brief connection hint.
 *
 * renderPopup is a pure DOM-rendering function (unit-tested). The bottom
 * of this file is the bootstrap that reads chrome.storage state and
 * wires Approve/Cancel callbacks to chrome.storage writes the background
 * script picks up.
 */

import { TrustStore } from '../trust-store.js';
import { normalisePendingPair } from '../lib/pending-pair.js';

const HIGH_RISK_KEYWORDS = ['bank', 'gov', 'mil'];

/**
 * UI labels for the inner-verb capabilities surfaced in the pair popup.
 * Each entry includes a short human-readable label and a `warn` flag —
 * when true, the popup decorates the entry with a visible warning so
 * the user notices the asymmetric privilege.
 */
interface CapabilityDisplay {
  label: string;
  warn: boolean;
}
const CAPABILITY_DISPLAY: Record<string, CapabilityDisplay> = {
  fetch: { label: 'HTTP fetches', warn: false },
  read_cookies: { label: 'Read cookies', warn: true },
  read_local_storage: { label: 'Read localStorage', warn: true },
  read_session_storage: { label: 'Read sessionStorage', warn: true },
  capture_request_header: { label: 'Capture request header', warn: true },
  read_indexed_db: { label: 'Read IndexedDB', warn: true },
};

/**
 * 0.4.0+: snapshot of the previously approved scope for an MCP. When
 * present on a `pending-pair` state, the popup renders an "update"
 * diff instead of a fresh-pair card.
 */
export interface PreviousScope {
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { urlPattern: string; headerName: string }[];
  indexedDbScopes: { origin: string; database: string; store: string; keys: string[] }[];
  localStoragePointers: { key: string; jsonPointer: string }[];
  sessionStoragePointers: { key: string; jsonPointer: string }[];
}

export interface PendingPair {
  serverName: string;
  version: string;
  /**
   * Non-empty array of hostnames the MCP declared. The popup renders
   * each as a separate list entry so the user can see exactly which
   * sites this MCP would gain access to.
   */
  domains: string[];
  /**
   * Non-empty array of capabilities the MCP declared (e.g. `['fetch']`
   * or `['fetch', 'read_cookies']`). Rendered as a bullet list with
   * warning markers next to elevated-trust verbs like `read_cookies`.
   */
  capabilities: string[];
  /**
   * 0.3.0+: declared scope arrays. Each renders into a sub-list under
   * the capability that uses it, so the user sees exactly which keys /
   * headers they are approving by name. Empty arrays render nothing.
   */
  cookieKeys?: string[];
  localStorageKeys?: string[];
  sessionStorageKeys?: string[];
  captureHeaders?: { urlPattern: string; headerName: string }[];
  /**
   * 0.4.0+: declared IndexedDB scopes (origin + database + store +
   * keys). Each scope is rendered on its own line so the user sees
   * exactly which DB / store names this MCP would read.
   */
  indexedDbScopes?: {
    origin: string;
    database: string;
    store: string;
    keys: string[];
  }[];
  pairCode: string;
}

export interface TrustedSummary {
  serverName: string;
  domains: string[];
  capabilities?: string[];
  /**
   * 0.4.2+: the SHA-256 hash of the MCP's X25519 identity pub. Used as
   * the chrome.storage.local trust-record key, and as the argument to
   * `TrustStore.remove(...)` when the user clicks revoke in the popup.
   * Optional in older callers; required for the revoke button to render.
   */
  identityHash?: string;
}

export type PopupState =
  | { mode: 'empty' }
  | {
      mode: 'status';
      trusted: TrustedSummary[];
      /**
       * 0.4.2+: invoked with the trusted entry's `identityHash` when
       * the user clicks the revoke (✕) button. The popup calls
       * `TrustStore.remove(identityHash)` and re-renders. Optional —
       * absent in unit-tests that don't exercise the revoke flow.
       */
      onRevoke?: (identityHash: string) => void;
    }
  | {
      mode: 'pending-pair';
      pending: PendingPair;
      /**
       * 0.4.0+: when this is a re-pair (scope changed since last
       * approval), the popup gets the previous scope so it can
       * render added / removed entries explicitly. Absent on a
       * fresh pair.
       */
      previous?: PreviousScope;
      onApprove: () => void;
      onCancel: () => void;
    };

function isHighRisk(domain: string): boolean {
  const d = domain.toLowerCase();
  return HIGH_RISK_KEYWORDS.some((k) => d.includes(k));
}

function anyHighRisk(domains: readonly string[]): boolean {
  return domains.some(isHighRisk);
}

function appendScopeSubList(
  dl: HTMLElement,
  label: string,
  keys: readonly string[] | undefined,
): void {
  if (!keys || keys.length === 0) return;
  dl.appendChild(elem('dt', { class: 'cap-warn' }, label));
  const dd = elem('dd', { class: 'cap-warn' });
  const ul = elem('ul', { class: 'scope-keys' });
  for (const k of keys) ul.appendChild(elem('li', {}, k));
  dd.appendChild(ul);
  dl.appendChild(dd);
}

function appendCaptureHeadersSubList(
  dl: HTMLElement,
  entries: readonly { urlPattern: string; headerName: string }[] | undefined,
): void {
  if (!entries || entries.length === 0) return;
  dl.appendChild(elem('dt', { class: 'cap-warn' }, 'Capture request header'));
  const dd = elem('dd', { class: 'cap-warn' });
  const ul = elem('ul', { class: 'capture-headers' });
  for (const e of entries) {
    ul.appendChild(elem('li', {}, `"${e.headerName}" from ${e.urlPattern}`));
  }
  dd.appendChild(ul);
  dl.appendChild(dd);
}

function captureHeaderKey(h: { urlPattern: string; headerName: string }): string {
  return `${h.headerName} from ${h.urlPattern}`;
}

function idbScopeKey(s: {
  origin: string;
  database: string;
  store: string;
  keys: string[];
}): string {
  return `${s.database}/${s.store}: ${[...s.keys].sort().join(', ')}`;
}

function pointerKey(p: { key: string; jsonPointer: string }): string {
  return `${p.key}${p.jsonPointer}`;
}

function diffLists<T>(
  prev: readonly T[],
  curr: readonly T[],
  keyOf: (x: T) => string,
): { added: T[]; removed: T[]; kept: T[] } {
  const prevKeys = new Set(prev.map(keyOf));
  const currKeys = new Set(curr.map(keyOf));
  const added = curr.filter((x) => !prevKeys.has(keyOf(x)));
  const removed = prev.filter((x) => !currKeys.has(keyOf(x)));
  const kept = curr.filter((x) => prevKeys.has(keyOf(x)));
  return { added, removed, kept };
}

/**
 * 0.4.0+: append three sub-sections (Previously approved / Now
 * requesting / No longer requested) summarising the diff between the
 * previous and current scope. Renders only items that differ from
 * the previous scope as "(new)" / "(removed)", with everything else
 * shown under "Previously approved".
 */
function appendDiffSummary(
  root: HTMLElement,
  pending: PendingPair,
  previous: PreviousScope,
): void {
  const dl = elem('dl', { class: 'scope-diff' });

  // Capabilities (compared as strings).
  const capDiff = diffLists(previous.capabilities, pending.capabilities, (x) => x);
  // Cookies / local / session storage keys (strings).
  const cookDiff = diffLists(
    previous.cookieKeys,
    pending.cookieKeys ?? [],
    (x) => x,
  );
  const localDiff = diffLists(
    previous.localStorageKeys,
    pending.localStorageKeys ?? [],
    (x) => x,
  );
  const sessDiff = diffLists(
    previous.sessionStorageKeys,
    pending.sessionStorageKeys ?? [],
    (x) => x,
  );
  const chDiff = diffLists(
    previous.captureHeaders,
    pending.captureHeaders ?? [],
    captureHeaderKey,
  );
  const idbDiff = diffLists(
    previous.indexedDbScopes,
    pending.indexedDbScopes ?? [],
    idbScopeKey,
  );
  const lpDiff = diffLists(
    previous.localStoragePointers,
    [],
    pointerKey,
  );
  const spDiff = diffLists(
    previous.sessionStoragePointers,
    [],
    pointerKey,
  );

  function pushSection(label: 'Previously approved' | 'Now requesting (new)' | 'No longer requested'): void {
    dl.appendChild(elem('dt', {}, label));
  }

  function appendBullet(text: string): void {
    const dd = elem('dd', {}, text);
    dl.appendChild(dd);
  }

  // Previously approved (= prev list minus removed).
  pushSection('Previously approved');
  const keptAny =
    capDiff.kept.length +
    cookDiff.kept.length +
    localDiff.kept.length +
    sessDiff.kept.length +
    chDiff.kept.length +
    idbDiff.kept.length;
  if (keptAny === 0) {
    appendBullet('(none)');
  } else {
    for (const c of capDiff.kept) appendBullet(`Capability: ${c}`);
    for (const k of cookDiff.kept) appendBullet(`Cookie: ${k}`);
    for (const k of localDiff.kept) appendBullet(`localStorage: ${k}`);
    for (const k of sessDiff.kept) appendBullet(`sessionStorage: ${k}`);
    for (const h of chDiff.kept) appendBullet(`Capture: ${h.headerName} from ${h.urlPattern}`);
    for (const s of idbDiff.kept) appendBullet(`IndexedDB: ${s.database}/${s.store}`);
  }

  // Now requesting (new).
  pushSection('Now requesting (new)');
  const addedAny =
    capDiff.added.length +
    cookDiff.added.length +
    localDiff.added.length +
    sessDiff.added.length +
    chDiff.added.length +
    idbDiff.added.length;
  if (addedAny === 0) {
    appendBullet('(none)');
  } else {
    for (const c of capDiff.added) appendBullet(`Capability: ${c}`);
    for (const k of cookDiff.added) appendBullet(`Cookie: ${k}`);
    for (const k of localDiff.added) appendBullet(`localStorage: ${k}`);
    for (const k of sessDiff.added) appendBullet(`sessionStorage: ${k}`);
    for (const h of chDiff.added) appendBullet(`Capture: ${h.headerName} from ${h.urlPattern}`);
    for (const s of idbDiff.added) appendBullet(`IndexedDB: ${s.database}/${s.store}`);
  }

  // No longer requested.
  pushSection('No longer requested');
  const removedAny =
    capDiff.removed.length +
    cookDiff.removed.length +
    localDiff.removed.length +
    sessDiff.removed.length +
    chDiff.removed.length +
    idbDiff.removed.length +
    lpDiff.removed.length +
    spDiff.removed.length;
  if (removedAny === 0) {
    appendBullet('(none)');
  } else {
    for (const c of capDiff.removed) appendBullet(`Capability: ${c}`);
    for (const k of cookDiff.removed) appendBullet(`Cookie: ${k}`);
    for (const k of localDiff.removed) appendBullet(`localStorage: ${k}`);
    for (const k of sessDiff.removed) appendBullet(`sessionStorage: ${k}`);
    for (const h of chDiff.removed) appendBullet(`Capture: ${h.headerName} from ${h.urlPattern}`);
    for (const s of idbDiff.removed) appendBullet(`IndexedDB: ${s.database}/${s.store}`);
  }

  root.appendChild(dl);
}

function appendIndexedDbScopesSubList(
  dl: HTMLElement,
  entries:
    | readonly { origin: string; database: string; store: string; keys: string[] }[]
    | undefined,
): void {
  if (!entries || entries.length === 0) return;
  dl.appendChild(elem('dt', { class: 'cap-warn' }, 'Read IndexedDB'));
  const dd = elem('dd', { class: 'cap-warn' });
  const ul = elem('ul', { class: 'indexed-db-scopes' });
  for (const e of entries) {
    ul.appendChild(
      elem(
        'li',
        {},
        `${e.database}/${e.store}: ${e.keys.join(', ')}`,
      ),
    );
  }
  dd.appendChild(ul);
  dl.appendChild(dd);
}

function elem<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Partial<Record<string, string>> = {},
  text?: string,
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== undefined) e.setAttribute(k, v);
  }
  if (text !== undefined) e.textContent = text;
  return e;
}

export function renderPopup(root: HTMLElement, state: PopupState): void {
  root.innerHTML = '';

  if (state.mode === 'empty') {
    root.appendChild(
      elem('p', {}, 'No MCP servers connected. Start an MCP server, then refresh.'),
    );
    return;
  }

  if (state.mode === 'status') {
    root.appendChild(elem('h3', {}, 'Trusted MCPs'));
    if (state.trusted.length === 0) {
      root.appendChild(elem('p', { class: 'hint' }, 'No trusted MCPs yet.'));
      return;
    }
    const ul = elem('ul', { class: 'trusted-list' });
    for (const t of state.trusted) {
      const li = elem('li', { class: 'trusted-entry' });
      li.appendChild(
        elem('span', { class: 'trusted-label' }, `${t.serverName} → ${t.domains.join(', ')}`),
      );
      // 0.4.2+: revoke button. Only rendered when both an onRevoke
      // callback and an identityHash are available — older tests and
      // legacy callers without identityHash still get the read-only
      // list as before.
      if (state.onRevoke && t.identityHash) {
        const btn = elem(
          'button',
          { 'data-action': 'revoke', 'data-identity-hash': t.identityHash, title: 'Revoke trust' },
          '✕',
        );
        btn.addEventListener('click', () => {
          // Inline confirmation — the popup is too small for a modal.
          if (!window.confirm(`Revoke trust for ${t.serverName}?`)) return;
          state.onRevoke!(t.identityHash!);
        });
        li.appendChild(btn);
      }
      ul.appendChild(li);
    }
    root.appendChild(ul);
    return;
  }

  // pending-pair
  const { pending, onApprove, onCancel } = state;
  const previous = state.previous;

  root.appendChild(
    elem(
      'h3',
      {},
      previous
        ? `${pending.serverName} wants to UPDATE its access`
        : 'Approve new MCP connection?',
    ),
  );

  if (previous) {
    appendDiffSummary(root, pending, previous);
  }

  const dl = elem('dl');
  dl.appendChild(elem('dt', {}, 'Server'));
  dl.appendChild(elem('dd', {}, `${pending.serverName} v${pending.version}`));
  dl.appendChild(elem('dt', {}, pending.domains.length === 1 ? 'Domain' : 'Domains'));
  const dd = elem('dd');
  const ulDomains = elem('ul', { class: 'domains' });
  for (const d of pending.domains) {
    ulDomains.appendChild(elem('li', {}, d));
  }
  dd.appendChild(ulDomains);
  dl.appendChild(dd);
  // Capability list. Always render — every MCP declares at least one
  // capability (or defaults to ['fetch']). The warning marker on
  // read_cookies makes the elevated trust visible without needing the
  // user to know what each verb means. Defensive: callers in test code
  // may omit `capabilities`, in which case we fall back to ['fetch'].
  const caps = pending.capabilities && pending.capabilities.length > 0
    ? pending.capabilities
    : ['fetch'];
  dl.appendChild(elem('dt', {}, 'Capabilities'));
  const ddCaps = elem('dd');
  const ulCaps = elem('ul', { class: 'capabilities' });
  for (const cap of caps) {
    const display = CAPABILITY_DISPLAY[cap] ?? { label: cap, warn: true };
    const li = elem(
      'li',
      display.warn ? { class: 'cap-warn' } : {},
      display.warn ? `${display.label} ⚠️` : display.label,
    );
    ulCaps.appendChild(li);
  }
  ddCaps.appendChild(ulCaps);
  dl.appendChild(ddCaps);

  // 0.3.0+: itemise each non-empty scope array. The user approves the
  // exact set of names, not just "this MCP can read storage" — so the
  // pair popup MUST show them.
  appendScopeSubList(dl, 'Read cookies', pending.cookieKeys);
  appendScopeSubList(dl, 'Read localStorage', pending.localStorageKeys);
  appendScopeSubList(dl, 'Read sessionStorage', pending.sessionStorageKeys);
  appendCaptureHeadersSubList(dl, pending.captureHeaders);
  appendIndexedDbScopesSubList(dl, pending.indexedDbScopes);

  root.appendChild(dl);

  if (anyHighRisk(pending.domains)) {
    const hr = pending.domains.find(isHighRisk) ?? pending.domains[0]!;
    root.appendChild(
      elem('p', { class: 'warn' }, `WARNING: ${hr} looks high-risk.`),
    );
  }

  root.appendChild(elem('div', { class: 'pair-code' }, pending.pairCode));

  root.appendChild(
    elem(
      'p',
      { class: 'hint' },
      "Verify this code matches the one shown in the server's terminal before approving.",
    ),
  );

  const btnRow = elem('div', { class: 'btn-row' });

  const cancel = elem('button', { 'data-action': 'cancel', autofocus: 'true' }, 'Cancel');
  cancel.addEventListener('click', onCancel);

  const approve = elem(
    'button',
    { 'data-action': 'approve' },
    previous ? 'Approve update' : 'Approve',
  );
  approve.addEventListener('click', onApprove);

  btnRow.appendChild(cancel);
  btnRow.appendChild(approve);
  root.appendChild(btnRow);
}

// -------------------------------------------------------------------
// Bootstrap (runs in popup context only — skipped in tests)
// -------------------------------------------------------------------

interface PendingPairRecord {
  mcpId: string;
  serverName: string;
  version: string;
  domains: string[];
  capabilities: string[];
  cookieKeys?: string[];
  localStorageKeys?: string[];
  sessionStorageKeys?: string[];
  captureHeaders?: { urlPattern: string; headerName: string }[];
  indexedDbScopes?: { origin: string; database: string; store: string; keys: string[] }[];
  localStoragePointers?: { key: string; jsonPointer: string }[];
  sessionStoragePointers?: { key: string; jsonPointer: string }[];
  previousScope?: PreviousScope;
  pairCode: string;
  identityHash: string;
  identityX25519Pub: string;
  identityEd25519Pub: string;
  sessionNonceB64: string;
}

declare const chrome: {
  runtime?: { getManifest: () => { version: string } };
  storage?: {
    local: {
      get: (k: string | string[]) => Promise<Record<string, unknown>>;
      set: (kv: Record<string, unknown>) => Promise<void>;
      remove: (k: string) => Promise<void>;
    };
  };
};

/**
 * Local alias bound to this file's `PendingPairRecord` type. The shared
 * helper in `../lib/pending-pair.ts` is generic, so the popup and the
 * background SW agree on what counts as a malformed input — see that
 * file for the full migration story.
 */
function readPendingDict(stored: unknown): Record<string, PendingPairRecord> {
  return normalisePendingPair<PendingPairRecord>(stored);
}

async function bootstrap(): Promise<void> {
  const root = document.getElementById('root');
  if (!root) return;
  if (typeof chrome === 'undefined' || !chrome.storage) {
    renderPopup(root, { mode: 'empty' });
    return;
  }

  // Hoisted so onApprove/onCancel can re-render the next entry without
  // re-reading from storage (storage gets the write but we want immediate
  // visual feedback, before the next popup open).
  const renderNext = async (): Promise<void> => {
    const got = await chrome.storage!.local.get(['pendingPair']);
    const dict = readPendingDict(got['pendingPair']);
    const entries = Object.values(dict);
    if (entries.length === 0) {
      // No more pending; fall through to the trusted-MCPs status view.
      await renderTrustedStatus();
      return;
    }
    // Show the first pending entry. Deterministic order keeps re-renders
    // stable for the user (entry insertion order from storage.get).
    const pending = entries[0]!;
    renderPopup(root, {
      mode: 'pending-pair',
      pending: {
        serverName: pending.serverName,
        version: pending.version,
        domains: [...pending.domains],
        capabilities: [...(pending.capabilities ?? ['fetch'])],
        cookieKeys: [...(pending.cookieKeys ?? [])],
        localStorageKeys: [...(pending.localStorageKeys ?? [])],
        sessionStorageKeys: [...(pending.sessionStorageKeys ?? [])],
        captureHeaders: (pending.captureHeaders ?? []).map((d) => ({ ...d })),
        indexedDbScopes: (pending.indexedDbScopes ?? []).map((d) => ({
          origin: d.origin,
          database: d.database,
          store: d.store,
          keys: [...d.keys],
        })),
        pairCode: pending.pairCode,
      },
      ...(pending.previousScope ? { previous: pending.previousScope } : {}),
      onApprove: () => {
        void (async () => {
          // Persist approval (background SW picks it up via the onChanged
          // listener and runs onApproval -> trust.put + ready frame).
          await chrome.storage!.local.set({ approvedPair: pending });
          // Remove THIS entry from the pending dict. Other unpaired MCPs
          // stay queued so the user can advance through them.
          const cur = await chrome.storage!.local.get(['pendingPair']);
          const d = readPendingDict(cur['pendingPair']);
          delete d[pending.mcpId];
          if (Object.keys(d).length === 0) {
            await chrome.storage!.local.remove('pendingPair');
          } else {
            await chrome.storage!.local.set({ pendingPair: d });
          }
          await renderNext();
        })();
      },
      onCancel: () => {
        void (async () => {
          const cur = await chrome.storage!.local.get(['pendingPair']);
          const d = readPendingDict(cur['pendingPair']);
          delete d[pending.mcpId];
          if (Object.keys(d).length === 0) {
            await chrome.storage!.local.remove('pendingPair');
          } else {
            await chrome.storage!.local.set({ pendingPair: d });
          }
          await renderNext();
        })();
      },
    });
  };

  const renderTrustedStatus = async (): Promise<void> => {
    const ev2 = chrome.runtime?.getManifest().version ?? '0.2.0';
    const trust2 = new TrustStore(ev2);
    const records = await trust2.list();
    const trustedList = Object.entries(records).map(([identityHash, r]) => ({
      identityHash,
      serverName: r.serverName,
      domains: [...r.domains],
      capabilities: r.capabilities ? [...r.capabilities] : ['fetch'],
    }));
    if (trustedList.length === 0) {
      renderPopup(root, { mode: 'empty' });
    } else {
      const onRevoke = (identityHash: string): void => {
        void trust2.remove(identityHash).then(() => renderTrustedStatus());
      };
      renderPopup(root, { mode: 'status', trusted: trustedList, onRevoke });
    }
  };

  // Branch: pending pairs take precedence over the status list. If no
  // pending pairs, render the trusted-MCPs status view.
  const got0 = await chrome.storage.local.get(['pendingPair']);
  const dict0 = readPendingDict(got0['pendingPair']);
  if (Object.keys(dict0).length > 0) {
    await renderNext();
  } else {
    await renderTrustedStatus();
  }
}

// Only run in popup context, not under vitest.
if (
  typeof document !== 'undefined' &&
  typeof window !== 'undefined' &&
  document.getElementById('root')
) {
  // In jsdom tests we put <div id="root"></div> in document.body but we
  // don't want bootstrap firing on import. The check below distinguishes:
  // a real popup has chrome.storage; jsdom doesn't.
  if (typeof (globalThis as { chrome?: unknown }).chrome !== 'undefined') {
    void bootstrap();
  }
}
