/**
 * `read_cookies` and `write_cookies` verb handlers, moved verbatim out of
 * `background.ts`.
 *
 * The read trio ships together because `handleReadCookiesRequest` narrows on
 * `'tabUrl' in req.init` to pick one of two PROTOCOL VERSIONS of the same
 * verb, not two unrelated code paths: legacy 0.2.0 reads `document.cookie`
 * through a content script, while 0.3.0 reads through `chrome.cookies.get`
 * because that is the only HttpOnly-visible path. Splitting them would hide
 * that the two branches must stay answer-compatible.
 *
 * `partialWriteError` lives here rather than in a shared errors module: it
 * defines the error SHAPE of the one non-transactional writer in the bridge,
 * and means nothing away from it.
 *
 * This module is the one most exposed to the `@types/chrome` hazard, so the
 * local chrome declaration below is load-bearing, not decoration:
 * `cookieSetDetailsFor` returns `sameSite?: string`, whereas `@types/chrome`
 * types `SetDetails.sameSite` as a literal union — under the ambient types
 * the `chrome.cookies.set(...)` call would not compile. The `?` on
 * `chrome.cookies` is likewise a real manifest-permission check (guarded
 * twice below), not a typo.
 */

import {
  undeclaredKeys,
  type InnerRequestReadCookies,
  type InnerRequestWriteCookies,
  type WriteCookieDecl,
} from '@fetchproxy/protocol';

import type { ChromeApi, ChromeCookie } from '../../chrome-api.js';
import { isUrlAllowedForAnyDomain, isTabUrlMatch, cookieUrlFor } from '../../lib/url-match.js';
import { sendToFirstResponsiveTab } from '../../lib/send-to-responsive-tab.js';
import { sendInner } from '../send-inner.js';
import { mcpCookieKeys } from '../session-scope.js';

declare const chrome: ChromeApi;

export async function handleReadCookiesRequest(
  mcpId: string,
  req: InnerRequestReadCookies,
  domains: string[],
): Promise<void> {
  // Two shapes: legacy 0.2.0 `{ tabUrl }` (returns raw document.cookie via
  // content script) vs new 0.3.0 `{ origin, keys }` (returns a values map
  // via chrome.cookies.get, which is HttpOnly-visible). Narrow on which
  // field is present — the validator already guaranteed it's one or the
  // other, not both.
  if ('tabUrl' in req.init) {
    await handleReadCookiesLegacy(mcpId, req.id, req.init.tabUrl, domains);
    return;
  }
  const cookieKeys = mcpCookieKeys.get(mcpId) ?? [];
  await handleReadCookiesV3(
    mcpId,
    req.id,
    req.init.origin,
    req.init.keys,
    domains,
    cookieKeys,
    req.init.path,
  );
}

async function handleReadCookiesLegacy(
  mcpId: string,
  id: number,
  tabUrl: string,
  domains: string[],
): Promise<void> {
  if (!isUrlAllowedForAnyDomain(tabUrl, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `tabUrl ${tabUrl} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` — see the
  // helper's doc for the per-tab iteration rationale (in short: a
  // pre-reload tab can shadow a fresh one if we only `.find()` the
  // first match).
  const result = await sendToFirstResponsiveTab(
    (t) => isTabUrlMatch(t, tabUrl),
    () => ({ kind: 'fetchproxy-read-cookies' }),
    tabUrl,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `tab read_cookies failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as { ok: true; cookies: string } | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: true,
      op: 'read_cookies',
      cookies: resp.cookies,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: resp.error,
    });
  }
}

async function handleReadCookiesV3(
  mcpId: string,
  id: number,
  origin: string,
  keys: string[],
  domains: string[],
  declaredCookieKeys: string[],
  path?: string,
): Promise<void> {
  // Origin must be in declared domain set. Checked on the BARE origin, before
  // any path is appended — the gate is about which host we may read, and a
  // path must never be able to influence that decision.
  if (!isUrlAllowedForAnyDomain(origin, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `origin ${origin} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // Every requested key must be in the declared cookieKeys set. This is
  // gate #2 (the server-side has its own gate #1) — defense in depth.
  // 0.4.0: declared keys may include trailing-* glob patterns; route
  // through the shared `matchesDeclaredKey` helper so the extension
  // and server agree on what counts as "in the declared set".
  const undeclared = undeclaredKeys(keys, declaredCookieKeys);
  if (undeclared.length > 0) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `cookie keys not in declared set: ${undeclared.join(', ')}`,
    });
    return;
  }
  if (!chrome.cookies) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: 'chrome.cookies API not available (extension missing the "cookies" permission?)',
    });
    return;
  }
  // Probe each requested key through chrome.cookies.get. This is the HttpOnly-
  // visible path — that's the whole reason 0.3.0 exists. Missing keys are
  // omitted from the response (no nulls), matching the contract.
  const values: Record<string, string> = {};
  for (const key of keys) {
    try {
      const got = await chrome.cookies.get({ url: cookieUrlFor(origin, path), name: key });
      if (got && typeof got.value === 'string') {
        values[key] = got.value;
      }
    } catch {
      // ignore individual cookie failure; missing key just stays absent
    }
  }
  await sendInner(mcpId, {
    type: 'response',
    id,
    ok: true,
    op: 'read_cookies',
    values,
  });
}

/**
 * The gate half of `write_cookies`, factored out (mirrors
 * `resolveReadDomRequest`) so the security decisions are unit-testable without
 * the module's live WS/session state.
 *
 * Refuses the WHOLE request rather than filtering it down: a rotation applied
 * to some of its cookies leaves the session in a state neither side expects,
 * which is worse than not writing at all.
 */
export function resolveWriteCookiesRequest(
  req: InnerRequestWriteCookies,
  domains: string[],
  declaredCookieKeys: string[],
): { ok: true } | { ok: false; error: string } {
  // Decided on the BARE origin, before any path is appended — the gate is
  // about which host we may write, and a path must never influence it.
  if (!isUrlAllowedForAnyDomain(req.init.origin, domains)) {
    return {
      ok: false,
      error: `origin ${req.init.origin} not in domains [${domains.join(', ')}]`,
    };
  }
  // Gate #2. Writes can never reach a cookie the MCP was not already trusted
  // to read, so granting `write_cookies` cannot widen WHICH cookies are in
  // play — only what may be done to the ones the user already approved.
  const undeclared = undeclaredKeys(
    req.init.cookies.map((c) => c.name),
    declaredCookieKeys,
  );
  if (undeclared.length > 0) {
    return { ok: false, error: `cookie keys not in declared set: ${undeclared.join(', ')}` };
  }
  return { ok: true };
}

/**
 * Build the `chrome.cookies.set` payload that OVERWRITES `existing` rather
 * than shadowing it.
 *
 * Passing only `{url, name, value}` looks like it works and quietly creates a
 * SECOND cookie: Chrome derives a host-only, non-HttpOnly, default-path cookie
 * from the URL, which does not replace a `Domain=`-scoped or HttpOnly
 * original. The site keeps reading the stale one — precisely the silent
 * failure this verb exists to prevent. So every attribute is copied off the
 * cookie being replaced.
 *
 * Two fields must be OMITTED rather than passed as undefined:
 *   - `domain` on a host-only cookie, which Chrome would otherwise read as a
 *     request to widen it into a domain cookie;
 *   - `expirationDate` on a session cookie, which would otherwise turn a
 *     persistent cookie into a session one.
 */
export function cookieSetDetailsFor(
  url: string,
  decl: WriteCookieDecl,
  existing: ChromeCookie,
): {
  url: string; name: string; value: string; domain?: string; path?: string;
  secure?: boolean; httpOnly?: boolean; sameSite?: string; expirationDate?: number;
  storeId?: string;
} {
  return {
    url,
    name: decl.name,
    value: decl.value,
    ...(existing.hostOnly ? {} : { domain: existing.domain }),
    path: existing.path,
    secure: existing.secure,
    httpOnly: existing.httpOnly,
    // Every optional attribute is spread conditionally, not passed as
    // undefined. `domain` and `expirationDate` are the two where the
    // difference is known to be load-bearing; `sameSite` and `storeId` follow
    // the same rule so the next reader doesn't have to work out which of the
    // four are special — and so a future Chrome that distinguishes
    // absent-from-undefined can't quietly change behaviour here.
    ...(existing.sameSite === undefined ? {} : { sameSite: existing.sameSite }),
    ...(existing.expirationDate === undefined ? {} : { expirationDate: existing.expirationDate }),
    ...(existing.storeId === undefined ? {} : { storeId: existing.storeId }),
  };
}

/**
 * Error text for a batch that failed partway through.
 *
 * Names what landed, because "the write failed" and "the write failed after
 * rotating two of your three cookies" call for different recovery, and the
 * caller cannot tell them apart from a bare message.
 */
function partialWriteError(name: string, cause: string, written: string[]): string {
  const base = `failed to write cookie ${name}: ${cause}`;
  return written.length === 0
    ? `${base} (no cookies were changed)`
    : `${base} (already written: ${written.join(', ')} — the jar is partially updated)`;
}

/**
 * 1.12.0+: overwrite the value of cookies the MCP is already trusted to read.
 *
 * The only write path in the bridge. It exists because sites that ROTATE a
 * credential cookie otherwise sign the user out of their own browser: the MCP
 * refreshes, the site issues a new value, and the copy in the cookie jar is
 * dead. Reading cannot repair that.
 *
 * Three gates, in order, all refusing the WHOLE request rather than applying
 * part of it — a half-written rotation is worse than a failed one:
 *
 *  1. origin must be in the declared domain set (checked on the bare origin,
 *     before any path, so a path can never influence the decision);
 *  2. every name must be in the declared `cookieKeys` — writes cannot reach a
 *     cookie the user did not already approve for reading;
 *  3. every named cookie must already EXIST. This verb refreshes a value in
 *     place; it does not author new cookies. Refusing here is what keeps a
 *     write capability from becoming a cookie-injection primitive.
 *
 * The gates are all-or-nothing, but the writes themselves cannot be: there is
 * no transaction over `chrome.cookies`, so a failure partway through a batch
 * leaves the earlier cookies already rotated. That case reports which names
 * landed (see {@link partialWriteError}) rather than a bare failure, because
 * an MCP that believes nothing was written will retry the whole batch against
 * a jar that is already half-updated.
 *
 * The existing cookie's attributes are copied onto the write. Passing only
 * `{url, name, value}` would look like it worked and quietly create a SECOND
 * cookie — Chrome derives a host-only, non-HttpOnly, default-path cookie from
 * the URL, which does not replace a `Domain=`-scoped or HttpOnly original. The
 * site would keep reading the stale one, which is exactly the silent failure
 * this verb exists to prevent. `hostOnly` decides whether `domain` may be sent
 * at all: Chrome rejects `domain` on a host-only cookie.
 */
export async function handleWriteCookiesRequest(
  mcpId: string,
  req: InnerRequestWriteCookies,
  domains: string[],
): Promise<void> {
  const { origin, path, cookies } = req.init;
  const fail = async (error: string): Promise<void> => {
    await sendInner(mcpId, { type: 'response', id: req.id, ok: false, op: 'write_cookies', error });
  };
  const gate = resolveWriteCookiesRequest(req, domains, mcpCookieKeys.get(mcpId) ?? []);
  if (!gate.ok) {
    await fail(gate.error);
    return;
  }
  if (!chrome.cookies) {
    await fail('chrome.cookies API not available (extension missing the "cookies" permission?)');
    return;
  }
  const url = cookieUrlFor(origin, path);
  // Resolve every target first, so an absent cookie aborts before anything is
  // written rather than halfway through.
  const targets: { decl: WriteCookieDecl; existing: ChromeCookie }[] = [];
  const missing: string[] = [];
  for (const decl of cookies) {
    let existing: ChromeCookie | null = null;
    try {
      existing = await chrome.cookies.get({ url, name: decl.name });
    } catch {
      existing = null;
    }
    if (existing) targets.push({ decl, existing });
    else missing.push(decl.name);
  }
  if (missing.length > 0) {
    await fail(
      `cookies not present to overwrite: ${missing.join(', ')} — write_cookies refreshes an ` +
        'existing value, it does not create cookies',
    );
    return;
  }
  const written: string[] = [];
  for (const { decl, existing } of targets) {
    try {
      // Chrome resolves the written Cookie on success and `null` on failure
      // WITHOUT throwing. Reporting `written` on "didn't throw" alone would
      // hand back a success for a write that never landed — the same silent
      // staleness this verb exists to prevent.
      const result = await chrome.cookies.set(cookieSetDetailsFor(url, decl, existing));
      if (!result) {
        await fail(partialWriteError(decl.name, 'chrome.cookies.set returned null', written));
        return;
      }
      written.push(decl.name);
    } catch (e) {
      await fail(partialWriteError(decl.name, String(e), written));
      return;
    }
  }
  await sendInner(mcpId, {
    type: 'response',
    id: req.id,
    ok: true,
    op: 'write_cookies',
    written,
  });
}
