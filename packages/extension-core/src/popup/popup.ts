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
import {
  REMOTE_TARGETS_KEY,
  normaliseRemoteTargets,
  validateRemoteTargetToken,
  validateRemoteTargetUrl,
  type RemoteTarget,
} from '../remote-targets.js';

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
export const CAPABILITY_DISPLAY: Record<string, CapabilityDisplay> = {
  fetch: { label: 'HTTP fetches', warn: false },
  read_cookies: { label: 'Read cookies', warn: true },
  read_local_storage: { label: 'Read localStorage', warn: true },
  read_session_storage: { label: 'Read sessionStorage', warn: true },
  capture_request_header: { label: 'Capture request header', warn: true },
  read_indexed_db: { label: 'Read IndexedDB', warn: true },
  read_dom: { label: 'Read DOM elements', warn: true },
  graphql: { label: 'Run declared GraphQL queries', warn: true },
  download: { label: 'Download files to your computer', warn: true },
  // The only capability that CHANGES state in the browser rather than
  // reading it. Labelled to say so outright — 'write cookies' alone reads
  // as a sibling of the reads above, and it is not one.
  write_cookies: {
    label: 'Overwrite cookies it can already read (can change your signed-in session)',
    warn: true,
  },
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
  captureHeaders: { host: string; path?: string; headerName: string }[];
  indexedDbScopes: { origin: string; database: string; store: string; keys: string[] }[];
  domSelectors: { name: string; selector: string; attribute?: string }[];
  graphqlOps: { name: string; operationName: string }[];
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
  captureHeaders?: { host: string; path?: string; headerName: string }[];
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
  /**
   * 1.4.0+: declared DOM selectors (name + CSS selector + optional
   * attribute). Each is rendered on its own line so the user sees exactly
   * which DOM values this MCP would read.
   */
  domSelectors?: { name: string; selector: string; attribute?: string }[];
  /**
   * 1.x+: declared GraphQL operations (name + operationName). Each is
   * rendered on its own line so the user sees exactly which operations
   * this MCP would invoke through the tab's own Apollo client.
   */
  graphqlOps?: { name: string; operationName: string }[];
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
  /**
   * Part 3: whether an instance of this identity is currently connected
   * (≥1 live session). Green dot when true; grey dot when false. Omitted
   * in older callers — no dot rendered when absent.
   */
  connected?: boolean;
}

/**
 * Part 2: scope info for a `scope-update` state. Mirrors the shape of
 * `PreviousScope` but represents the DECLARED (new) scope the MCP wants.
 */
export interface ScopeSnapshot {
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { host: string; path?: string; headerName: string }[];
  indexedDbScopes: { origin: string; database: string; store: string; keys: string[] }[];
  domSelectors: { name: string; selector: string; attribute?: string }[];
  graphqlOps: { name: string; operationName: string }[];
  localStoragePointers: { key: string; jsonPointer: string }[];
  sessionStoragePointers: { key: string; jsonPointer: string }[];
}

/**
 * A configured remote bridge as the popup shows it — never the credential.
 * The token is write-only from here: it goes into storage on save and is
 * never read back out for display, so a shoulder-surfed popup discloses which
 * relay this browser talks to and not the right to talk to it.
 */
export interface RemoteTargetView {
  id: string;
  url: string;
  label?: string;
  enabled: boolean;
  /**
   * Whether this bridge's socket is open right now. Undefined when the
   * background did not answer — the row then renders without a dot rather
   * than claiming a state nobody vouched for.
   */
  connected?: boolean;
}

export interface BridgesView {
  targets: RemoteTargetView[];
  /** Whether the loopback link — the one every local MCP needs — is up. */
  localConnected?: boolean;
  /** Save a new target. Returns an error string to show, or null on success. */
  onAdd?: (input: { url: string; token: string; label: string }) => Promise<string | null>;
  onRemove?: (id: string) => void;
  onToggle?: (id: string, enabled: boolean) => void;
}

export type PopupState =
  | { mode: 'empty'; bridges?: BridgesView }
  | {
      mode: 'status';
      trusted: TrustedSummary[];
      /**
       * 2.1.0+: the bridges this browser dials. Optional — a popup rendered
       * without it looks exactly as it did before remote targets existed,
       * which is what keeps every prior test honest.
       */
      bridges?: BridgesView;
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
    }
  | {
      /**
       * Part 2: non-blocking scope-growth offer. The MCP is already
       * connected with the approved (intersection) scope. The user
       * can Grant the wider scope or dismiss (keep as is).
       */
      mode: 'scope-update';
      serverName: string;
      /** The FULL declared scope the MCP now wants. */
      pending: ScopeSnapshot;
      /** The previously approved scope — used as the diff baseline. */
      previous: PreviousScope;
      /** [Grant]: write the declared scope to trust (via onApproval). */
      onGrant: () => void;
      /** [Keep as is]: dismiss without writing trust. */
      onKeepAsIs: () => void;
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
  entries: readonly { host: string; path?: string; headerName: string }[] | undefined,
): void {
  if (!entries || entries.length === 0) return;
  dl.appendChild(elem('dt', { class: 'cap-warn' }, 'Capture request header'));
  const dd = elem('dd', { class: 'cap-warn' });
  const ul = elem('ul', { class: 'capture-headers' });
  for (const e of entries) {
    ul.appendChild(elem('li', {}, `"${e.headerName}" from ${captureHeaderTarget(e)}`));
  }
  dd.appendChild(ul);
  dl.appendChild(dd);
}

/** Human-readable capture target `host` + `path` (omitted path ≡ `/*`). */
function captureHeaderTarget(h: { host: string; path?: string }): string {
  return `${h.host}${h.path ?? '/*'}`;
}

function captureHeaderKey(h: { host: string; path?: string; headerName: string }): string {
  return `${h.headerName} from ${captureHeaderTarget(h)}`;
}

function idbScopeKey(s: {
  origin: string;
  database: string;
  store: string;
  keys: string[];
}): string {
  return `${s.database}/${s.store}: ${[...s.keys].sort().join(', ')}`;
}

function domSelectorKey(s: { name: string; selector: string; attribute?: string }): string {
  return `${s.name}\x00${s.selector}\x00${s.attribute ?? ''}`;
}

/** Human-readable label for a DOM selector: `name → selector` (+ `[attr]`). */
function domSelectorLabel(s: { name: string; selector: string; attribute?: string }): string {
  return `${s.name} → ${s.selector}${s.attribute ? ` [${s.attribute}]` : ''}`;
}

function pointerKey(p: { key: string; jsonPointer: string }): string {
  return `${p.key}${p.jsonPointer}`;
}

function graphqlOpKey(g: { name: string; operationName: string }): string {
  return `${g.name}\x00${g.operationName}`;
}

/** Human-readable label for a declared GraphQL op: `name → operationName`. */
function graphqlOpLabel(g: { name: string; operationName: string }): string {
  return `${g.name} → ${g.operationName}`;
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
  const domDiff = diffLists(
    previous.domSelectors,
    pending.domSelectors ?? [],
    domSelectorKey,
  );
  const graphDiff = diffLists(
    previous.graphqlOps,
    pending.graphqlOps ?? [],
    graphqlOpKey,
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
    idbDiff.kept.length +
    domDiff.kept.length +
    graphDiff.kept.length;
  if (keptAny === 0) {
    appendBullet('(none)');
  } else {
    for (const c of capDiff.kept) appendBullet(`Capability: ${c}`);
    for (const k of cookDiff.kept) appendBullet(`Cookie: ${k}`);
    for (const k of localDiff.kept) appendBullet(`localStorage: ${k}`);
    for (const k of sessDiff.kept) appendBullet(`sessionStorage: ${k}`);
    for (const h of chDiff.kept) appendBullet(`Capture: ${h.headerName} from ${captureHeaderTarget(h)}`);
    for (const s of idbDiff.kept) appendBullet(`IndexedDB: ${s.database}/${s.store}`);
    for (const s of domDiff.kept) appendBullet(`DOM: ${domSelectorLabel(s)}`);
    for (const g of graphDiff.kept) appendBullet(`GraphQL: ${graphqlOpLabel(g)}`);
  }

  // Now requesting (new).
  pushSection('Now requesting (new)');
  const addedAny =
    capDiff.added.length +
    cookDiff.added.length +
    localDiff.added.length +
    sessDiff.added.length +
    chDiff.added.length +
    idbDiff.added.length +
    domDiff.added.length +
    graphDiff.added.length;
  if (addedAny === 0) {
    appendBullet('(none)');
  } else {
    for (const c of capDiff.added) appendBullet(`Capability: ${c}`);
    for (const k of cookDiff.added) appendBullet(`Cookie: ${k}`);
    for (const k of localDiff.added) appendBullet(`localStorage: ${k}`);
    for (const k of sessDiff.added) appendBullet(`sessionStorage: ${k}`);
    for (const h of chDiff.added) appendBullet(`Capture: ${h.headerName} from ${captureHeaderTarget(h)}`);
    for (const s of idbDiff.added) appendBullet(`IndexedDB: ${s.database}/${s.store}`);
    for (const s of domDiff.added) appendBullet(`DOM: ${domSelectorLabel(s)}`);
    for (const g of graphDiff.added) appendBullet(`GraphQL: ${graphqlOpLabel(g)}`);
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
    domDiff.removed.length +
    graphDiff.removed.length +
    lpDiff.removed.length +
    spDiff.removed.length;
  if (removedAny === 0) {
    appendBullet('(none)');
  } else {
    for (const c of capDiff.removed) appendBullet(`Capability: ${c}`);
    for (const k of cookDiff.removed) appendBullet(`Cookie: ${k}`);
    for (const k of localDiff.removed) appendBullet(`localStorage: ${k}`);
    for (const k of sessDiff.removed) appendBullet(`sessionStorage: ${k}`);
    for (const h of chDiff.removed) appendBullet(`Capture: ${h.headerName} from ${captureHeaderTarget(h)}`);
    for (const s of idbDiff.removed) appendBullet(`IndexedDB: ${s.database}/${s.store}`);
    for (const s of domDiff.removed) appendBullet(`DOM: ${domSelectorLabel(s)}`);
    for (const g of graphDiff.removed) appendBullet(`GraphQL: ${graphqlOpLabel(g)}`);
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

function appendDomSelectorsSubList(
  dl: HTMLElement,
  entries:
    | readonly { name: string; selector: string; attribute?: string }[]
    | undefined,
): void {
  if (!entries || entries.length === 0) return;
  dl.appendChild(elem('dt', { class: 'cap-warn' }, 'Read DOM elements'));
  const dd = elem('dd', { class: 'cap-warn' });
  const ul = elem('ul', { class: 'dom-selectors' });
  for (const e of entries) {
    ul.appendChild(elem('li', {}, domSelectorLabel(e)));
  }
  dd.appendChild(ul);
  dl.appendChild(dd);
}

function appendGraphqlOpsSubList(
  dl: HTMLElement,
  entries: readonly { name: string; operationName: string }[] | undefined,
): void {
  if (!entries || entries.length === 0) return;
  dl.appendChild(elem('dt', { class: 'cap-warn' }, 'Run declared GraphQL queries'));
  const dd = elem('dd', { class: 'cap-warn' });
  const ul = elem('ul', { class: 'graphql-ops' });
  for (const e of entries) {
    ul.appendChild(elem('li', {}, graphqlOpLabel(e)));
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

/**
 * Build one `<li>` for the trusted-MCPs list: optional connection-status dot,
 * the `serverName → domains` label, and (when revokable) the ✕ button.
 * Shared by the flat list and the Active/Inactive sectioned views.
 */
function buildTrustedEntry(
  t: TrustedSummary,
  onRevoke?: (identityHash: string) => void,
): HTMLLIElement {
  const li = elem('li', { class: 'trusted-entry' });
  // Connection-status dot — only when `connected` is explicitly set, so
  // legacy callers and tests without the live-session path are unchanged.
  if (t.connected !== undefined) {
    li.appendChild(
      elem('span', {
        class: `status-dot ${t.connected ? 'connected' : 'offline'}`,
        'aria-label': t.connected ? 'connected' : 'not connected',
        title: t.connected ? 'Connected' : 'Not connected',
      }),
    );
  }
  li.appendChild(
    elem('span', { class: 'trusted-label' }, `${t.serverName} → ${t.domains.join(', ')}`),
  );
  // Revoke button — only when both an onRevoke callback and an identityHash
  // are available (older tests/callers get the read-only list as before).
  if (onRevoke && t.identityHash) {
    const btn = elem(
      'button',
      { 'data-action': 'revoke', 'data-identity-hash': t.identityHash, title: 'Revoke trust' },
      '✕',
    );
    btn.addEventListener('click', () => {
      // Inline confirmation — the popup is too small for a modal.
      if (!window.confirm(`Revoke trust for ${t.serverName}?`)) return;
      onRevoke(t.identityHash!);
    });
    li.appendChild(btn);
  }
  return li;
}


/** The green/grey dot a bridge row carries, with the state named for a11y. */
function statusDot(connected: boolean): HTMLElement {
  return elem('span', {
    class: connected ? 'status-dot connected' : 'status-dot offline',
    'aria-label': connected ? 'connected' : 'offline',
    title: connected ? 'connected' : 'not connected',
  });
}

/**
 * The bridges section: where this browser is willing to answer MCPs from.
 *
 * Loopback is rendered as a fixed row rather than an entry, because it is not
 * configuration — it cannot be removed or repointed, and showing it as though
 * it could would misdescribe what a remote target is (an addition, never a
 * replacement).
 *
 * Adding one is deliberately a two-field form with visible validation rather
 * than a paste-anything box: the URL decides who this browser's signed-in
 * sessions can be asked to act for, so a typo should fail here, in front of
 * the person making the decision, rather than in a reconnect loop.
 */
function appendBridges(root: HTMLElement, bridges: BridgesView): void {
  root.appendChild(elem('h3', {}, 'Bridges'));

  const ul = elem('ul', { class: 'bridge-list' });
  const local = elem('li', { class: 'bridge local' });
  // The dot is per LINK, and the loopback row is the reason. A single
  // connection state goes green as soon as ANY bridge is up, which is exactly
  // when a dead local concentrator — the one every MCP on this machine needs —
  // stops being visible.
  if (bridges.localConnected !== undefined) local.appendChild(statusDot(bridges.localConnected));
  local.appendChild(elem('span', { class: 'bridge-url' }, 'localhost (always on)'));
  ul.appendChild(local);

  for (const t of bridges.targets) {
    const li = elem('li', { class: t.enabled ? 'bridge remote' : 'bridge remote disabled' });
    li.setAttribute('data-target-id', t.id);
    if (bridges.onToggle) {
      const box = elem('input', { type: 'checkbox', class: 'bridge-enabled' });
      (box as HTMLInputElement).checked = t.enabled;
      box.addEventListener('change', () => {
        bridges.onToggle!(t.id, (box as HTMLInputElement).checked);
      });
      li.appendChild(box);
    }
    if (t.connected !== undefined) li.appendChild(statusDot(t.connected));
    li.appendChild(elem('span', { class: 'bridge-url' }, t.label ? `${t.label} — ${t.url}` : t.url));
    if (bridges.onRemove) {
      const rm = elem('button', { class: 'bridge-remove', 'aria-label': `remove ${t.url}` }, '✕');
      rm.addEventListener('click', () => bridges.onRemove!(t.id));
      li.appendChild(rm);
    }
    ul.appendChild(li);
  }
  root.appendChild(ul);

  if (!bridges.onAdd) return;

  const form = elem('div', { class: 'bridge-add' });
  const url = elem('input', { type: 'text', class: 'bridge-url-input', placeholder: 'wss://host/bridge' });
  const token = elem('input', { type: 'password', class: 'bridge-token-input', placeholder: 'bridge token' });
  const label = elem('input', { type: 'text', class: 'bridge-label-input', placeholder: 'label (optional)' });
  const err = elem('p', { class: 'bridge-error hint' });
  const save = elem('button', { class: 'bridge-save' }, 'Add bridge');

  save.addEventListener('click', () => {
    const urlValue = (url as HTMLInputElement).value.trim();
    const tokenValue = (token as HTMLInputElement).value.trim();
    const urlCheck = validateRemoteTargetUrl(urlValue);
    if (!urlCheck.ok) {
      err.textContent = `Bridge URL: ${urlCheck.reason}`;
      return;
    }
    const tokenCheck = validateRemoteTargetToken(tokenValue);
    if (!tokenCheck.ok) {
      err.textContent = `Bridge token: ${tokenCheck.reason}`;
      return;
    }
    err.textContent = '';
    void Promise.resolve(
      bridges.onAdd!({ url: urlValue, token: tokenValue, label: (label as HTMLInputElement).value.trim() }),
    ).then((problem) => {
      if (problem) err.textContent = problem;
    });
  });

  form.appendChild(url);
  form.appendChild(token);
  form.appendChild(label);
  form.appendChild(save);
  form.appendChild(err);
  root.appendChild(form);

  root.appendChild(
    elem(
      'p',
      { class: 'hint' },
      'A bridge can ask this browser to pair with MCPs it hosts. Add one only if you run it.',
    ),
  );
}

export function renderPopup(root: HTMLElement, state: PopupState): void {
  root.innerHTML = '';

  if (state.mode === 'empty') {
    root.appendChild(
      elem('p', {}, 'No MCP servers connected. Start an MCP server, then refresh.'),
    );
    if (state.bridges) appendBridges(root, state.bridges);
    return;
  }

  if (state.mode === 'status') {
    root.appendChild(elem('h3', {}, 'Trusted MCPs'));
    if (state.trusted.length === 0) {
      root.appendChild(elem('p', { class: 'hint' }, 'No trusted MCPs yet.'));
      if (state.bridges) appendBridges(root, state.bridges);
      return;
    }
    const onRevoke = state.onRevoke;
    // Alphabetical by serverName (case-insensitive), stable within a group.
    const byName = (a: TrustedSummary, b: TrustedSummary): number =>
      a.serverName.localeCompare(b.serverName, undefined, { sensitivity: 'base' });
    const sorted = [...state.trusted].sort(byName);

    const buildList = (entries: TrustedSummary[]): HTMLElement => {
      const ul = elem('ul', { class: 'trusted-list' });
      for (const t of entries) ul.appendChild(buildTrustedEntry(t, onRevoke));
      return ul;
    };

    // Split into Active (currently connected) / Inactive only when the
    // background supplied connection info (≥1 entry has `connected` set).
    // Legacy callers / unit tests with no connection info get a single
    // sorted list, unchanged. A header is rendered only for a non-empty
    // section, so all-active shows just "Active" and vice versa.
    const hasConnInfo = sorted.some((t) => t.connected !== undefined);
    if (hasConnInfo) {
      const active = sorted.filter((t) => t.connected === true);
      const inactive = sorted.filter((t) => t.connected !== true);
      if (active.length > 0) {
        root.appendChild(elem('h4', { class: 'trusted-section' }, `Active (${active.length})`));
        root.appendChild(buildList(active));
      }
      if (inactive.length > 0) {
        // Collapsed by default — the currently-connected (Active) MCPs are
        // what matter day-to-day; the rest tuck behind a native <details>
        // disclosure the user can expand. No `open` attr ⇒ starts closed.
        const details = elem('details', { class: 'trusted-inactive' });
        details.appendChild(
          elem('summary', { class: 'trusted-section' }, `Inactive (${inactive.length})`),
        );
        details.appendChild(buildList(inactive));
        root.appendChild(details);
      }
    } else {
      root.appendChild(buildList(sorted));
    }
    if (state.bridges) appendBridges(root, state.bridges);
    return;
  }

  if (state.mode === 'scope-update') {
    const { serverName, pending, previous, onGrant, onKeepAsIs } = state;
    root.appendChild(
      elem('h3', {}, `${serverName} wants to expand its access`),
    );
    // Reuse the existing diff renderer — `pending` is a ScopeSnapshot which
    // is structurally compatible with PendingPair for the diff fields.
    appendDiffSummary(root, {
      serverName,
      version: '',
      domains: [],
      capabilities: pending.capabilities,
      cookieKeys: pending.cookieKeys,
      localStorageKeys: pending.localStorageKeys,
      sessionStorageKeys: pending.sessionStorageKeys,
      captureHeaders: pending.captureHeaders,
      indexedDbScopes: pending.indexedDbScopes,
      domSelectors: pending.domSelectors,
      graphqlOps: pending.graphqlOps,
      pairCode: '',
    }, previous);

    const btnRow = elem('div', { class: 'btn-row' });
    const keepBtn = elem('button', { 'data-action': 'keep-as-is', autofocus: 'true' }, 'Keep as is');
    keepBtn.addEventListener('click', onKeepAsIs);
    const grantBtn = elem('button', { 'data-action': 'grant' }, 'Grant');
    grantBtn.addEventListener('click', onGrant);
    btnRow.appendChild(keepBtn);
    btnRow.appendChild(grantBtn);
    root.appendChild(btnRow);
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
  //
  // 1.12.0+: `cookieKeys` is also the writable set when `write_cookies` is
  // granted, and this sub-list is the only place those names appear. Heading
  // it "Read cookies" there would understate the request at the moment the
  // user decides — and contradict the capability line above, which says
  // "Overwrite …".
  appendScopeSubList(
    dl,
    // `caps`, not `pending.capabilities` — the local above is the guarded
    // form, and it exists because callers may omit the field. Reading it
    // directly throws, and a popup that throws renders nothing at all, which
    // is a worse outcome than a wrong heading.
    caps.includes('write_cookies') ? 'Read and overwrite cookies' : 'Read cookies',
    pending.cookieKeys,
  );
  appendScopeSubList(dl, 'Read localStorage', pending.localStorageKeys);
  appendScopeSubList(dl, 'Read sessionStorage', pending.sessionStorageKeys);
  appendCaptureHeadersSubList(dl, pending.captureHeaders);
  appendIndexedDbScopesSubList(dl, pending.indexedDbScopes);
  appendDomSelectorsSubList(dl, pending.domSelectors);
  appendGraphqlOpsSubList(dl, pending.graphqlOps);

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

// 0.6.0+: keyed by `${identityHash}:${scopeHash}`, carries mcpIds[].
interface PendingPairRecord {
  key: string;
  kind: 'pair';
  identityHash: string;
  mcpIds: string[];
  sessionNonces: Record<string, string>;
  serverName: string;
  version: string;
  domains: string[];
  capabilities: string[];
  cookieKeys?: string[];
  localStorageKeys?: string[];
  sessionStorageKeys?: string[];
  captureHeaders?: { host: string; path?: string; headerName: string }[];
  indexedDbScopes?: { origin: string; database: string; store: string; keys: string[] }[];
  domSelectors?: { name: string; selector: string; attribute?: string }[];
  graphqlOps?: { name: string; operationName: string }[];
  localStoragePointers?: { key: string; jsonPointer: string }[];
  sessionStoragePointers?: { key: string; jsonPointer: string }[];
  previousScope?: PreviousScope;
  pairCode: string;
  identityX25519Pub: string;
  identityEd25519Pub: string;
}

/** Part 2: non-blocking scope-update offer. MCP is already connected. */
interface PendingScopeUpdateRecord {
  key: string;
  kind: 'scope-update';
  identityHash: string;
  mcpIds: string[];
  serverName: string;
  version: string;
  domains: string[];
  capabilities: string[];
  cookieKeys?: string[];
  localStorageKeys?: string[];
  sessionStorageKeys?: string[];
  captureHeaders?: { host: string; path?: string; headerName: string }[];
  indexedDbScopes?: { origin: string; database: string; store: string; keys: string[] }[];
  domSelectors?: { name: string; selector: string; attribute?: string }[];
  graphqlOps?: { name: string; operationName: string }[];
  localStoragePointers?: { key: string; jsonPointer: string }[];
  sessionStoragePointers?: { key: string; jsonPointer: string }[];
  previousScope: PreviousScope;
  identityX25519Pub: string;
  identityEd25519Pub: string;
}

type AnyPendingRecord = PendingPairRecord | PendingScopeUpdateRecord;

/** One entry of the background's link-status answer (background/links.ts). */
interface LinkStatusMessage {
  id: string;
  connected: boolean;
}

declare const chrome: {
  runtime?: {
    getManifest: () => { version: string };
    sendMessage?: (msg: unknown) => Promise<unknown>;
    onMessage?: {
      addListener: (
        cb: (
          msg: unknown,
          _sender: unknown,
          sendResponse: (r: unknown) => void,
        ) => boolean | void,
      ) => void;
    };
  };
  storage?: {
    local: {
      get: (k: string | string[]) => Promise<Record<string, unknown>>;
      set: (kv: Record<string, unknown>) => Promise<void>;
      remove: (k: string) => Promise<void>;
    };
  };
};

/**
 * Local alias bound to this file's `AnyPendingRecord` union. The shared
 * helper in `../lib/pending-pair.ts` is generic, so the popup and the
 * background SW agree on what counts as a malformed input — see that
 * file for the full migration story.
 */
function readPendingDict(stored: unknown): Record<string, AnyPendingRecord> {
  return normalisePendingPair<AnyPendingRecord>(stored);
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

    // Helper: remove this entry and re-render.
    const removePendingAndContinue = async (): Promise<void> => {
      const cur = await chrome.storage!.local.get(['pendingPair']);
      const d = readPendingDict(cur['pendingPair']);
      delete d[pending.key];
      if (Object.keys(d).length === 0) {
        await chrome.storage!.local.remove('pendingPair');
      } else {
        await chrome.storage!.local.set({ pendingPair: d });
      }
      await renderNext();
    };

    if (pending.kind === 'scope-update') {
      renderPopup(root, {
        mode: 'scope-update',
        serverName: pending.serverName,
        pending: {
          capabilities: [...(pending.capabilities ?? [])],
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
          domSelectors: (pending.domSelectors ?? []).map((d) => ({ ...d })),
          graphqlOps: (pending.graphqlOps ?? []).map((d) => ({ ...d })),
          localStoragePointers: (pending.localStoragePointers ?? []).map((d) => ({ ...d })),
          sessionStoragePointers: (pending.sessionStoragePointers ?? []).map((d) => ({ ...d })),
        },
        previous: pending.previousScope,
        onGrant: () => {
          void (async () => {
            // Write approvedPair — background SW picks it up via onChanged,
            // calls onApproval(scope-update) → trust.put with declared scope.
            await chrome.storage!.local.set({ approvedPair: pending });
            await removePendingAndContinue();
          })();
        },
        onKeepAsIs: () => {
          void (async () => {
            // Dismiss: write dismissedScopeUpdate — background SW records
            // the dismissed hash so this scope is not re-queued until changed.
            // Extract the declared scopeHash from the key (format: `${identityHash}:${scopeHash}`).
            const colonIdx = pending.key.indexOf(':');
            const dismissedHash = colonIdx >= 0 ? pending.key.slice(colonIdx + 1) : pending.key;
            await chrome.storage!.local.set({
              dismissedScopeUpdate: {
                key: pending.key,
                identityHash: pending.identityHash,
                scopeHash: dismissedHash,
              },
            });
            await removePendingAndContinue();
          })();
        },
      });
      return;
    }

    // kind === 'pair'
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
        domSelectors: (pending.domSelectors ?? []).map((d) => ({ ...d })),
        graphqlOps: (pending.graphqlOps ?? []).map((d) => ({ ...d })),
        pairCode: pending.pairCode,
      },
      ...(pending.previousScope ? { previous: pending.previousScope } : {}),
      onApprove: () => {
        void (async () => {
          // Persist approval (background SW picks it up via the onChanged
          // listener and runs onApproval -> trust.put + ready frame).
          await chrome.storage!.local.set({ approvedPair: pending });
          await removePendingAndContinue();
        })();
      },
      onCancel: () => {
        void removePendingAndContinue();
      },
    });
  };

  /**
   * Read the configured bridges and build the section's callbacks.
   *
   * Every write goes through `normaliseRemoteTargets` on the way back out, so
   * the popup can only ever persist rows the background will actually dial —
   * the two agree on what a target IS, in one place, rather than the popup
   * writing something the background silently drops.
   */
  const bridgesView = async (links: LinkStatusMessage[]): Promise<BridgesView> => {
    const got = await chrome.storage!.local.get(REMOTE_TARGETS_KEY);
    const targets = normaliseRemoteTargets(got[REMOTE_TARGETS_KEY]);
    const statusFor = (id: string): boolean | undefined =>
      links.find((link) => link.id === id)?.connected;
    const write = async (next: RemoteTarget[]): Promise<void> => {
      await chrome.storage!.local.set({ [REMOTE_TARGETS_KEY]: normaliseRemoteTargets(next) });
    };
    const localConnected = statusFor('local');
    return {
      ...(localConnected === undefined ? {} : { localConnected }),
      targets: targets.map((t) => {
        const connected = statusFor(`remote:${t.id}`);
        return {
          id: t.id,
          url: t.url,
          ...(t.label === undefined ? {} : { label: t.label }),
          enabled: t.enabled,
          ...(connected === undefined ? {} : { connected }),
        };
      }),
      onAdd: async ({ url, token, label }) => {
        if (targets.some((t) => t.url === url)) return 'That bridge is already configured.';
        const id = `b${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
        const next: RemoteTarget[] = [
          ...targets,
          { id, url, token, ...(label === '' ? {} : { label }), enabled: true },
        ];
        await write(next);
        if (normaliseRemoteTargets(next).length === targets.length) {
          return 'That bridge could not be saved — the list is full.';
        }
        await renderTrustedStatus();
        return null;
      },
      onRemove: (id) => {
        void write(targets.filter((t) => t.id !== id)).then(() => renderTrustedStatus());
      },
      onToggle: (id, enabled) => {
        void write(targets.map((t) => (t.id === id ? { ...t, enabled } : t))).then(() =>
          renderTrustedStatus(),
        );
      },
    };
  };

  const renderTrustedStatus = async (): Promise<void> => {
    const ev2 = chrome.runtime?.getManifest().version ?? '0.2.0';
    const trust2 = new TrustStore(ev2);
    const records = await trust2.list();
    // Part 3: query the background for the currently-connected identity set
    // so we can render the connection-status dot on each entry. Best-effort:
    // if the query fails (no background, old SW), fall back to no dot.
    let connectedHashes: Set<string> = new Set();
    // Link statuses ride the same query (boot.ts). Absent means the background
    // did not answer, and a bridge row then renders WITHOUT a dot rather than
    // claiming a state nobody vouched for.
    let links: LinkStatusMessage[] = [];
    if (chrome.runtime?.sendMessage) {
      try {
        const resp = await chrome.runtime.sendMessage({ type: 'get-connected-identities' }) as
          | { connectedHashes?: string[]; links?: LinkStatusMessage[] }
          | undefined;
        connectedHashes = new Set(resp?.connectedHashes ?? []);
        links = resp?.links ?? [];
      } catch {
        // Background not available — dots will be absent.
      }
    }
    const trustedList = Object.entries(records).map(([identityHash, r]) => ({
      identityHash,
      serverName: r.serverName,
      domains: [...r.domains],
      capabilities: r.capabilities ? [...r.capabilities] : ['fetch'],
      connected: connectedHashes.has(identityHash),
    }));
    const bridges = await bridgesView(links);
    if (trustedList.length === 0) {
      renderPopup(root, { mode: 'empty', bridges });
    } else {
      const onRevoke = (identityHash: string): void => {
        void trust2.remove(identityHash).then(() => renderTrustedStatus());
      };
      renderPopup(root, { mode: 'status', trusted: trustedList, onRevoke, bridges });
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

  // Part 3: listen for connection-change notifications from the background
  // service worker. When a session comes up or tears down, re-render the
  // status view so the dots update without the user closing/re-opening the
  // popup. Guard: `onMessage` is absent in jsdom / older environments.
  if (chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((msg) => {
      if (
        msg !== null &&
        typeof msg === 'object' &&
        (msg as { type?: unknown }).type === 'connections-changed'
      ) {
        void renderTrustedStatus();
      }
    });
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
