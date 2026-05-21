/**
 * Popup UI for the fetchproxy extension. Three modes:
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
}

export type PopupState =
  | { mode: 'empty' }
  | { mode: 'status'; trusted: TrustedSummary[] }
  | {
      mode: 'pending-pair';
      pending: PendingPair;
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
    const ul = elem('ul');
    for (const t of state.trusted) {
      ul.appendChild(elem('li', {}, `${t.serverName} → ${t.domains.join(', ')}`));
    }
    root.appendChild(ul);
    return;
  }

  // pending-pair
  const { pending, onApprove, onCancel } = state;

  root.appendChild(elem('h3', {}, 'Approve new MCP connection?'));

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

  const approve = elem('button', { 'data-action': 'approve' }, 'Approve');
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

async function bootstrap(): Promise<void> {
  const root = document.getElementById('root');
  if (!root) return;
  if (typeof chrome === 'undefined' || !chrome.storage) {
    renderPopup(root, { mode: 'empty' });
    return;
  }
  const got = await chrome.storage.local.get(['pendingPair']);
  const pending = got['pendingPair'] as PendingPairRecord | undefined;
  if (pending) {
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
      onApprove: () => {
        void chrome.storage!.local.set({ approvedPair: pending });
        void chrome.storage!.local.remove('pendingPair');
        renderPopup(root, { mode: 'status', trusted: [] });
      },
      onCancel: () => {
        void chrome.storage!.local.remove('pendingPair');
        renderPopup(root, { mode: 'empty' });
      },
    });
    return;
  }
  const ev = chrome.runtime?.getManifest().version ?? '0.2.0';
  const trust = new TrustStore(ev);
  const records = await trust.list();
  const trustedList = Object.values(records).map((r) => ({
    serverName: r.serverName,
    domains: [...r.domains],
    capabilities: r.capabilities ? [...r.capabilities] : ['fetch'],
  }));
  if (trustedList.length === 0) {
    renderPopup(root, { mode: 'empty' });
  } else {
    renderPopup(root, { mode: 'status', trusted: trustedList });
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
