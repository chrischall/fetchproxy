/**
 * `capture_request_header` and `capture_redirect` verb handlers, moved
 * verbatim out of `background.ts`.
 *
 * The only two consumers of `chrome.webRequest`, and they share one
 * lifecycle: register a SINGLE-SHOT listener, arm a timeout, then remove the
 * listener on whichever fires first. Those registrations must stay INSIDE the
 * handler bodies. Hoisting either `addListener` to module scope — the usual
 * MV3 idiom for top-level event wiring — would leave the listener installed
 * forever, so a later capture for one mcpId would be answered by a request
 * belonging to a different one.
 */

import type {
  InnerRequestCaptureRequestHeader,
  InnerRequestCaptureRedirect,
} from '@fetchproxy/protocol';

import type { ChromeApi } from '../../chrome-api.js';
import { isUrlAllowedForAnyDomain } from '../../lib/url-match.js';
import { sendInner } from '../send-inner.js';
import { mcpCaptureHeaders } from '../session-scope.js';

declare const chrome: ChromeApi;

/**
 * extraInfoSpec for the capture_request_header webRequest listener.
 * `'extraHeaders'` is REQUIRED: Chrome MV3 strips `Cookie` (and other
 * sensitive headers like `Authorization`) from `onBeforeSendHeaders`
 * details unless it is present — without it, a capture for `cookie` can
 * never match and times out. Exported so a regression test pins it.
 */
export const CAPTURE_EXTRA_INFO_SPEC = ['requestHeaders', 'extraHeaders'] as const;

export async function handleCaptureRequestHeaderRequest(
  mcpId: string,
  req: InnerRequestCaptureRequestHeader,
  domains: string[],
): Promise<void> {
  const declared = mcpCaptureHeaders.get(mcpId) ?? [];
  const reqPath = req.init.path ?? '/*';
  const declaredMatch = declared.find(
    (d) =>
      d.host === req.init.host &&
      (d.path ?? '/*') === reqPath &&
      d.headerName === req.init.headerName,
  );
  if (!declaredMatch) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: `(host, path, headerName) not in declared captureHeaders`,
    });
    return;
  }
  // The capture host must be a declared domain or a subdomain of one.
  const host = req.init.host;
  if (!isUrlAllowedForAnyDomain(`https://${host}/`, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: `capture host ${host} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  if (!chrome.webRequest) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: 'chrome.webRequest API not available (extension missing the "webRequest" permission?)',
    });
    return;
  }
  const timeoutMs = req.init.timeoutMs ?? 30_000;
  const wantedHeader = req.init.headerName.toLowerCase();
  let resolved = false;
  const listener = (details: {
    requestHeaders?: { name: string; value?: string }[];
  }): void => {
    if (resolved) return;
    const hdr = details.requestHeaders?.find((h) => h.name.toLowerCase() === wantedHeader);
    if (!hdr || typeof hdr.value !== 'string') return;
    resolved = true;
    try {
      chrome.webRequest!.onBeforeSendHeaders.removeListener(listener);
    } catch {
      // ignore
    }
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'capture_request_header',
      value: hdr.value,
    });
  };
  try {
    chrome.webRequest.onBeforeSendHeaders.addListener(
      listener,
      { urls: [`https://${req.init.host}${req.init.path ?? '/*'}`] },
      [...CAPTURE_EXTRA_INFO_SPEC],
    );
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: `webRequest listener registration failed: ${String(e)}`,
    });
    return;
  }
  setTimeout(() => {
    if (resolved) return;
    resolved = true;
    try {
      chrome.webRequest!.onBeforeSendHeaders.removeListener(listener);
    } catch {
      // ignore
    }
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: 'timeout',
    });
  }, timeoutMs);
}

/**
 * Snapshot the redirect target URL of the next request the browser makes
 * to `(host, path?)`, via `chrome.webRequest.onBeforeRedirect`. Single-
 * shot, mirrors `handleCaptureRequestHeaderRequest` but lighter: there's
 * no declared-scope plumbing — the only gate is that `host` is one of the
 * MCP's declared `domains` (equals-or-subdomain). Unlike
 * `onBeforeSendHeaders`, `onBeforeRedirect` needs no `extraInfoSpec`.
 */
export async function handleCaptureRedirectRequest(
  mcpId: string,
  req: InnerRequestCaptureRedirect,
  domains: string[],
): Promise<void> {
  // The watched host must be a declared domain or a subdomain of one.
  const host = req.init.host;
  if (!isUrlAllowedForAnyDomain(`https://${host}/`, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_redirect',
      error: `capture host ${host} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  if (!chrome.webRequest) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_redirect',
      error: 'chrome.webRequest API not available (extension missing the "webRequest" permission?)',
    });
    return;
  }
  const timeoutMs = req.init.timeoutMs ?? 30_000;
  let resolved = false;
  const listener = (details: { redirectUrl: string }): void => {
    if (resolved) return;
    if (typeof details.redirectUrl !== 'string' || details.redirectUrl.length === 0) return;
    resolved = true;
    try {
      chrome.webRequest!.onBeforeRedirect.removeListener(listener);
    } catch {
      // ignore
    }
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'capture_redirect',
      value: details.redirectUrl,
    });
  };
  try {
    chrome.webRequest.onBeforeRedirect.addListener(listener, {
      urls: [`https://${req.init.host}${req.init.path ?? '/*'}`],
    });
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_redirect',
      error: `webRequest listener registration failed: ${String(e)}`,
    });
    return;
  }
  setTimeout(() => {
    if (resolved) return;
    resolved = true;
    try {
      chrome.webRequest!.onBeforeRedirect.removeListener(listener);
    } catch {
      // ignore
    }
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_redirect',
      error: 'timeout',
    });
  }, timeoutMs);
}
