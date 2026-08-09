/**
 * `download` verb handler, moved verbatim out of `background.ts`.
 *
 * The sole consumer of `chrome.downloads`, and the only verb whose gate is
 * just `isUrlAllowedForAnyDomain` — it reads no per-session scope Map.
 *
 * **Local only, and refused over a remote bridge.** This verb answers with a
 * FILESYSTEM PATH on the machine running the browser, on the explicit
 * assumption that the MCP asking reads the same disk — true for every MCP on
 * `127.0.0.1`, and false for one reached through a relay. Two things go wrong
 * there rather than one: the path names a file the MCP cannot open, and a
 * remote MCP gets to write bytes into the user's Downloads folder, which is
 * the one verb in this protocol that leaves something behind on the machine.
 * So a `download` arriving on a remote link is refused with a reason the
 * calling MCP can print, instead of a path that will not resolve.
 *
 * Two orderings inside `handleDownloadRequest` are load-bearing and are
 * preserved exactly: `downloads.onChanged.addListener` is registered BEFORE
 * `downloads.download(...)` so a fast completion cannot be missed, and
 * `succeed()` sets `done = true` synchronously before its first `await` so
 * exactly one response frame is ever sent for a request.
 */

import type {
  InnerRequestDownload,
  DownloadResult,
} from '@fetchproxy/protocol';

import type { ChromeApi } from '../../chrome-api.js';
import { isUrlAllowedForAnyDomain } from '../../lib/url-match.js';
import { linkForMcp } from '../links.js';
import { sendInner } from '../send-inner.js';

declare const chrome: ChromeApi;

/**
 * Map a completed `chrome.downloads` item to a `download` response value.
 * `mime` / `finalUrl` are omitted when absent so the wire stays minimal (the
 * protocol validator treats both as optional). Exported for unit testing —
 * the surrounding async orchestration is exercised live, like other handlers.
 */
export function downloadValueFromItem(item: {
  filename: string;
  fileSize: number;
  mime?: string;
  finalUrl?: string;
}): DownloadResult {
  return {
    path: item.filename,
    // Chrome's `DownloadItem.fileSize` is documented to be `-1` when the
    // size is unknown (e.g. the server never sent Content-Length). The
    // `download` response validator requires a non-negative integer — an
    // unclamped -1 would throw `ProtocolError` server-side, and since that
    // throw happens inside host.ts's single message-handler try/catch, it
    // closes the WHOLE extension WebSocket (every MCP on the concentrator),
    // not just this request. Clamp instead of failing the whole download:
    // the file genuinely saved, only its size is unreported.
    bytes: item.fileSize < 0 ? 0 : item.fileSize,
    ...(item.mime ? { mime: item.mime } : {}),
    ...(item.finalUrl ? { finalUrl: item.finalUrl } : {}),
  };
}

/**
 * Download `url` via `chrome.downloads` — the BROWSER fetches it with the
 * user's real cookies + TLS/JA3 fingerprint, so it clears a Cloudflare
 * bot-challenge a page-level `fetch()` (cors) cannot, and follows the
 * cross-origin redirect to the final file. Resolves the saved local file
 * path + size (the bridge is loopback-only, so the MCP reads the same disk).
 * Only the `url` host needs to be a declared `domain`; chrome.downloads
 * follows redirects (e.g. to a presigned subdomain) on its own.
 */
export const DOWNLOAD_LOCAL_ONLY_ERROR =
  'download is local-only: it saves a file on the machine running this browser and answers with that ' +
  'machine\'s path, so an MCP reached through a remote bridge could neither open it nor should be ' +
  'writing files here. Run this MCP on the same machine as the browser to use download.';

export async function handleDownloadRequest(
  mcpId: string,
  req: InnerRequestDownload,
  domains: string[],
): Promise<void> {
  // Before the domain check on purpose: "this cannot work from there" is a
  // fact about the link, not about the URL, and answering it first keeps the
  // refusal identical whatever was asked for.
  if (linkForMcp(mcpId)?.kind === 'remote') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'download',
      error: DOWNLOAD_LOCAL_ONLY_ERROR,
    });
    return;
  }
  if (!isUrlAllowedForAnyDomain(req.init.url, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'download',
      error: `download url host not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  if (!chrome.downloads) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'download',
      error: 'chrome.downloads API not available (extension missing the "downloads" permission?)',
    });
    return;
  }
  const downloads = chrome.downloads;
  const timeoutMs = req.init.timeoutMs ?? 120_000;
  let done = false;
  let downloadId: number | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const cleanup = (): void => {
    try {
      downloads.onChanged.removeListener(onChanged);
    } catch {
      // ignore
    }
    if (timer !== undefined) clearTimeout(timer);
  };
  const fail = (error: string): void => {
    if (done) return;
    done = true;
    cleanup();
    void sendInner(mcpId, { type: 'response', id: req.id, ok: false, op: 'download', error });
  };
  const succeed = async (): Promise<void> => {
    if (done || downloadId === undefined) return;
    // Claim ownership BEFORE the first await: both the onChanged 'complete'
    // path and the post-download() race-guard can call succeed() while a prior
    // call is still awaiting search(), so set `done` synchronously to guarantee
    // exactly one response frame per request. The error paths below send
    // directly (fail() would no-op now that `done` is set).
    const id = downloadId;
    done = true;
    cleanup();
    let items;
    try {
      items = await downloads.search({ id });
    } catch (e) {
      void sendInner(mcpId, {
        type: 'response',
        id: req.id,
        ok: false,
        op: 'download',
        error: `download search failed: ${String(e)}`,
      });
      return;
    }
    const item = items[0];
    if (!item) {
      void sendInner(mcpId, {
        type: 'response',
        id: req.id,
        ok: false,
        op: 'download',
        error: 'download completed but its record was not found',
      });
      return;
    }
    // Erase only the download RECORD — the file stays for the MCP to move.
    void downloads.erase({ id }).catch(() => {
      // best-effort record cleanup
    });
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'download',
      value: downloadValueFromItem(item),
    });
  };
  const onChanged = (delta: {
    id: number;
    state?: { current: string };
    error?: { current: string };
  }): void => {
    if (downloadId === undefined || delta.id !== downloadId) return;
    if (delta.error?.current) {
      fail(`download interrupted: ${delta.error.current}`);
      return;
    }
    if (delta.state?.current === 'complete') {
      void succeed();
    } else if (delta.state?.current === 'interrupted') {
      fail('download interrupted');
    }
  };

  // Listener BEFORE the download so a fast completion isn't missed.
  downloads.onChanged.addListener(onChanged);
  timer = setTimeout(() => fail('timeout'), timeoutMs);

  try {
    downloadId = await downloads.download({
      url: req.init.url,
      ...(req.init.filename ? { filename: req.init.filename } : {}),
      conflictAction: 'uniquify',
      saveAs: false,
    });
  } catch (e) {
    fail(`download could not be started: ${String(e)}`);
    return;
  }
  // Race guard: a tiny file may finish before `download()` even resolved, so
  // the onChanged 'complete' delta could have fired while downloadId was unset.
  try {
    const [item] = await downloads.search({ id: downloadId });
    if (item?.state === 'complete') {
      void succeed();
    } else if (item?.state === 'interrupted') {
      fail(`download interrupted: ${item.error ?? 'unknown'}`);
    }
  } catch {
    // onChanged will still deliver the terminal state.
  }
}
