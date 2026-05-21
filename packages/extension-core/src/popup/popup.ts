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

export interface PendingPair {
  serverName: string;
  version: string;
  domain: string;
  pairCode: string;
}

export interface TrustedSummary {
  serverName: string;
  domain: string;
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
      ul.appendChild(elem('li', {}, `${t.serverName} → ${t.domain}`));
    }
    root.appendChild(ul);
    return;
  }

  // pending-pair
  const { pending, onApprove, onCancel } = state;

  root.appendChild(elem('h3', {}, 'Approve new MCP connection?'));

  const dl = elem('dl');
  const entries: [string, string][] = [
    ['Server', `${pending.serverName} v${pending.version}`],
    ['Domain', pending.domain],
  ];
  for (const [k, v] of entries) {
    dl.appendChild(elem('dt', {}, k));
    dl.appendChild(elem('dd', {}, v));
  }
  root.appendChild(dl);

  if (isHighRisk(pending.domain)) {
    root.appendChild(
      elem('p', { class: 'warn' }, `WARNING: ${pending.domain} looks high-risk.`),
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
  domain: string;
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
        domain: pending.domain,
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
  const ev = chrome.runtime?.getManifest().version ?? '0.1.0';
  const trust = new TrustStore(ev);
  const records = await trust.list();
  const trustedList = Object.values(records).map((r) => ({
    serverName: r.serverName,
    domain: r.domain,
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
