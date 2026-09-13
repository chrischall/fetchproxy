/**
 * The storage half of Task 4.3: what the refusal path writes down so the popup
 * can say it.
 *
 * The popup is a different context with a different lifetime — it is not
 * running when the hello arrives, and the service worker is usually not
 * running when the popup opens — so this cannot be a variable in `state`. It
 * is `chrome.storage.local`, and the shape and every rule about it live in
 * `lib/version-mismatch.ts`, which both contexts import. This module is only
 * the read-modify-write, plus the two things a store needs that a pure
 * function cannot have:
 *
 * 1. **Serialisation.** Two v3 MCPs on the loopback concentrator hello within
 *    a tick of each other, and two interleaved read-modify-writes would drop
 *    one of them — the popup would then name one of the two servers that need
 *    upgrading, which is worse than naming neither because it reads as a
 *    complete list. Every write goes through one promise chain.
 * 2. **A failure that is not fatal.** A popup line is diagnostics; a storage
 *    error must never take down the hello path that is already refusing a
 *    connection. Every failure is warned and swallowed.
 */

import { parseMcpId, PROTOCOL_VERSION } from '@fetchproxy/protocol';

import type { ChromeApi } from '../chrome-api.js';
import {
  VERSION_MISMATCH_KEY,
  clearVersionMismatches,
  freshVersionMismatches,
  normaliseVersionMismatches,
  recordVersionMismatch,
  type VersionMismatch,
} from '../lib/version-mismatch.js';

import type { Link } from './links.js';
import { broadcastConnectionsChanged } from './session-scope.js';

declare const chrome: ChromeApi;

/** The one write chain. See rule 1 above. */
let tail: Promise<void> = Promise.resolve();

function queue(work: () => Promise<void>): void {
  tail = tail.then(work).catch((e) => {
    console.warn('[fetchproxy] version-mismatch store:', e);
  });
}

async function read(): Promise<Record<string, VersionMismatch>> {
  const got = await chrome.storage.local.get(VERSION_MISMATCH_KEY);
  return normaliseVersionMismatches(got[VERSION_MISMATCH_KEY]);
}

/**
 * Tell the popup an MCP was refused for its protocol version.
 *
 * The `serverName` is parsed out of the `mcpId` rather than read off the
 * hello's own `serverName` field, which is why `peekHelloVersion` does not
 * return that field at all: this is a frame no validator accepted, and the id
 * is the one string on it whose SHAPE was checked.
 *
 * Recorded whether or not the MCP could be told on the wire — an MCP older
 * than 2.6.0 cannot hear `hello-rejected`, and that is precisely the case in
 * which the browser is the only place the refusal can land.
 */
export function noteVersionMismatch(link: Link, mcpId: string, mcpProtocol: number): void {
  queue(async () => {
    const now = Date.now();
    const next = recordVersionMismatch(freshVersionMismatches(await read(), now), {
      linkId: link.id,
      linkLabel: link.label,
      serverName: parseMcpId(mcpId).serverName,
      mcpProtocol,
      extensionProtocol: PROTOCOL_VERSION,
      at: now,
    });
    await chrome.storage.local.set({ [VERSION_MISMATCH_KEY]: next });
    // The popup re-renders on this — it is the "something you are showing has
    // changed" signal, not a claim about sessions — so an open popup contradicts
    // itself within the same second rather than at the next open.
    broadcastConnectionsChanged();
  });
}

/**
 * Forget what a successful v4 hello refutes: this server, on this link.
 *
 * Writes nothing when there was nothing to forget, which is the common case —
 * every hello on a healthy machine comes through here.
 */
export function forgetVersionMismatch(link: Link, mcpId: string): void {
  queue(async () => {
    const dict = await read();
    const next = clearVersionMismatches(dict, link.id, parseMcpId(mcpId).serverName);
    if (next === dict) return;
    await chrome.storage.local.set({ [VERSION_MISMATCH_KEY]: next });
    broadcastConnectionsChanged();
  });
}
