/**
 * Background service worker entry. Owns:
 *   - WS connections to each trusted MCP server (one per port)
 *   - Trust-prompt flow for new connections
 *   - Per-MCP domain allowlist enforcement on every fetch
 *   - Tab routing: pick a tab matching `init.tabUrl`, send fetch RPC
 *
 * Configuration is read from chrome.storage (a list of server ports
 * the user has added in the popup). Each entry is { port, name? }
 * — the actual server identity comes from its `hello` frame.
 */
import {
  validateFrame,
  type Frame,
  type HelloServer,
  type FetchRequest,
} from '@fetchproxy/protocol';
import { TrustStore, type McpIdentity } from './trust-store.js';
import { isUrlAllowedForDomain, isTabUrlMatch } from './lib/url-match.js';

const EXTENSION_VERSION = chrome.runtime.getManifest().version;
const PING_INTERVAL_MS = 20_000;
const STORAGE_PORTS_KEY = 'configuredPorts';

interface ConfiguredPort {
  port: number;
  /** Display name (user-supplied or last-seen server name). */
  label?: string;
}

interface Connection {
  port: number;
  ws: WebSocket;
  serverHello?: HelloServer;
  pingTimer?: ReturnType<typeof setInterval>;
}

const trust = new TrustStore(chrome.storage.local);
const connections = new Map<number, Connection>();

/** Open WebSocket connections to every configured port. Called on
 *  service worker startup + when the user adds/removes ports. */
async function reconcileConnections(): Promise<void> {
  const got = await chrome.storage.local.get(STORAGE_PORTS_KEY);
  const desired: ConfiguredPort[] = (got[STORAGE_PORTS_KEY] as ConfiguredPort[] | undefined) ?? [];

  // Close any connection to a port no longer configured.
  for (const [port, conn] of connections) {
    if (!desired.find((d) => d.port === port)) {
      conn.ws.close();
      if (conn.pingTimer) clearInterval(conn.pingTimer);
      connections.delete(port);
    }
  }
  // Open any newly-configured port.
  for (const d of desired) {
    if (!connections.has(d.port)) connect(d.port);
  }
}

function connect(port: number): void {
  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  const conn: Connection = { port, ws };
  connections.set(port, conn);

  ws.addEventListener('open', () => {
    ws.send(JSON.stringify({
      type: 'hello',
      role: 'extension',
      version: EXTENSION_VERSION,
      platform: 'chrome',
      extension_id: 'fetchproxy',
    }));
    conn.pingTimer = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, PING_INTERVAL_MS);
  });

  ws.addEventListener('message', async (ev) => {
    let frame: Frame;
    try {
      frame = validateFrame(JSON.parse(ev.data));
    } catch {
      ws.close(1002);
      return;
    }
    await handleFrame(conn, frame);
  });

  ws.addEventListener('close', () => {
    if (conn.pingTimer) clearInterval(conn.pingTimer);
    connections.delete(port);
    // Reconnect after 2s. Bound by service worker lifetime.
    setTimeout(() => {
      chrome.storage.local.get(STORAGE_PORTS_KEY).then((got) => {
        const stillConfigured = (got[STORAGE_PORTS_KEY] as ConfiguredPort[] | undefined)
          ?.find((d) => d.port === port);
        if (stillConfigured) connect(port);
      });
    }, 2000);
  });

  ws.addEventListener('error', () => {
    // The close handler will run too; nothing to do here.
  });
}

async function handleFrame(conn: Connection, frame: Frame): Promise<void> {
  switch (frame.type) {
    case 'hello':
      if (frame.role !== 'server') return;
      conn.serverHello = frame;
      // Check trust before sending ready.
      await maybePromptTrust(conn, frame);
      return;
    case 'ping':
      conn.ws.send(JSON.stringify({ type: 'pong' }));
      return;
    case 'pong':
      return;
    case 'request':
      await handleFetchRequest(conn, frame);
      return;
    default:
      return;
  }
}

async function maybePromptTrust(conn: Connection, hello: HelloServer): Promise<void> {
  const id: McpIdentity = {
    port: conn.port,
    server: hello.server,
    version: hello.version,
    domain: hello.domain,
  };
  const known = await trust.lookup(id);
  if (known?.approval === 'always') {
    // Already trusted. Verify a matching tab exists, then send ready.
    if (await hasMatchingTab(hello.domain)) {
      conn.ws.send(JSON.stringify({ type: 'ready' }));
    }
    return;
  }
  // Open the popup as a window with the trust prompt. The popup will
  // call trust.approve() or send a "block" message, then we re-evaluate.
  // For implementation simplicity we just queue a pending-trust state;
  // the popup polls trust-store on open.
  await chrome.storage.session.set({
    [`pendingTrust:${conn.port}`]: {
      ...id,
      requested_at: Date.now(),
    },
  });
  // Open popup window for the prompt.
  chrome.action.openPopup?.();
}

async function hasMatchingTab(domain: string): Promise<boolean> {
  const tabs = await chrome.tabs.query({});
  return tabs.some((t) => {
    if (!t.url) return false;
    try {
      const u = new URL(t.url);
      return u.hostname === domain || u.hostname.endsWith('.' + domain);
    } catch {
      return false;
    }
  });
}

async function handleFetchRequest(conn: Connection, req: FetchRequest): Promise<void> {
  const hello = conn.serverHello;
  if (!hello) {
    sendErr(conn, req.id, 'no server hello yet');
    return;
  }

  // Domain allowlist enforcement.
  if (!isUrlAllowedForDomain(req.init.url, hello.domain)) {
    sendErr(conn, req.id, `url not in allowed domain (${hello.domain}): ${req.init.url}`);
    return;
  }

  // Find a tab matching tabUrl.
  const tabs = await chrome.tabs.query({});
  const tab = tabs.find((t) => t.url && isTabUrlMatch(t.url, req.init.tabUrl));
  if (!tab || tab.id === undefined) {
    sendErr(conn, req.id, `no tab matching ${req.init.tabUrl}`);
    return;
  }

  try {
    const response = await chrome.tabs.sendMessage(tab.id, {
      kind: 'fetchproxy-fetch',
      init: req.init,
    });
    if (response?.ok) {
      conn.ws.send(JSON.stringify({
        type: 'response',
        id: req.id,
        ok: true,
        status: response.status,
        url: response.url,
        body: response.body,
      }));
    } else {
      sendErr(conn, req.id, response?.error ?? 'fetch failed');
    }
  } catch (e) {
    // Content script not injected — self-heal by injecting and retrying.
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js'],
      });
      const retry = await chrome.tabs.sendMessage(tab.id, {
        kind: 'fetchproxy-fetch',
        init: req.init,
      });
      if (retry?.ok) {
        conn.ws.send(JSON.stringify({
          type: 'response',
          id: req.id,
          ok: true,
          status: retry.status,
          url: retry.url,
          body: retry.body,
        }));
      } else {
        sendErr(conn, req.id, retry?.error ?? 'fetch failed after content-script re-inject');
      }
    } catch (e2) {
      sendErr(conn, req.id, `content script unreachable: ${(e2 as Error).message}`);
    }
  }
}

function sendErr(conn: Connection, id: number, error: string): void {
  conn.ws.send(JSON.stringify({ type: 'response', id, ok: false, error }));
}

// Service worker entry.
chrome.runtime.onInstalled.addListener(() => reconcileConnections());
chrome.runtime.onStartup.addListener(() => reconcileConnections());
chrome.storage.onChanged.addListener((changes) => {
  if (changes[STORAGE_PORTS_KEY]) reconcileConnections();
  // When the user approves a pending trust, re-evaluate the connection.
  for (const k of Object.keys(changes)) {
    if (k.startsWith('trustedMcp:')) {
      for (const [, conn] of connections) {
        if (conn.serverHello) {
          maybePromptTrust(conn, conn.serverHello).catch(() => {});
        }
      }
    }
  }
});

reconcileConnections();
