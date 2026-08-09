/**
 * `read_local_storage` and `read_session_storage` verb handlers, moved
 * verbatim out of `background.ts`.
 *
 * ONE function serves both verbs via the `bucket: 'local' | 'session'`
 * parameter, which selects among four declared-scope tables (keys and
 * pointers, local and session). The ternaries that do the selecting are
 * deliberately left spelled out: collapsing them into a lookup object is
 * exactly the edit that would hide a swapped local/session table, and the
 * consequence of that swap is a session-storage key answered out of the
 * local-storage allowlist.
 */

import {
  undeclaredKeys,
  type InnerRequestReadLocalStorage,
  type InnerRequestReadSessionStorage,
} from '@fetchproxy/protocol';

import { isUrlAllowedForAnyDomain, isTabUrlOnOrigin } from '../../lib/url-match.js';
import { sendToFirstResponsiveTab } from '../../lib/send-to-responsive-tab.js';
import { sendInner } from '../send-inner.js';
import {
  mcpLocalStorageKeys,
  mcpSessionStorageKeys,
  mcpLocalStoragePointers,
  mcpSessionStoragePointers,
} from '../session-scope.js';

export async function handleReadStorageRequest(
  mcpId: string,
  req: InnerRequestReadLocalStorage | InnerRequestReadSessionStorage,
  domains: string[],
  bucket: 'local' | 'session',
): Promise<void> {
  const op = req.op;
  // Pick the right declared-keys table by capability.
  const declaredKeys =
    bucket === 'local'
      ? (mcpLocalStorageKeys.get(mcpId) ?? [])
      : (mcpSessionStorageKeys.get(mcpId) ?? []);
  const declaredPointers =
    bucket === 'local'
      ? (mcpLocalStoragePointers.get(mcpId) ?? [])
      : (mcpSessionStoragePointers.get(mcpId) ?? []);
  if (!isUrlAllowedForAnyDomain(req.init.origin, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: `origin ${req.init.origin} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // 0.4.0: declared keys may include trailing-* glob patterns.
  const undeclared = undeclaredKeys(req.init.keys, declaredKeys);
  if (undeclared.length > 0) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: `${bucket}Storage keys not in declared set: ${undeclared.join(', ')}`,
    });
    return;
  }
  // 0.4.0: per-request pointers must each match a declared pair.
  if (req.init.pointers) {
    for (const [outputKey, p] of Object.entries(req.init.pointers)) {
      const match = declaredPointers.find(
        (d) => d.key === p.storageKey && d.jsonPointer === p.jsonPointer,
      );
      if (!match) {
        await sendInner(mcpId, {
          type: 'response',
          id: req.id,
          ok: false,
          op,
          error: `${bucket}Storage pointer (${p.storageKey}, ${p.jsonPointer}) not in declared set [outputKey=${outputKey}]`,
        });
        return;
      }
    }
  }
  // 0.4.1+: match by host-or-subdomain rather than strict prefix.
  // Apex origins (e.g. `https://hbportal.co`) routinely come from
  // multi-vendor MCPs whose real tabs live on a vendor subdomain.
  //
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` so a
  // pre-reload tab doesn't shadow a freshly-loaded one with the content
  // script — see the helper's doc.
  const result = await sendToFirstResponsiveTab(
    (t) => isTabUrlOnOrigin(t, req.init.origin),
    () => ({
      kind: bucket === 'local' ? 'fetchproxy-read-local-storage' : 'fetchproxy-read-session-storage',
      keys: [...req.init.keys],
      pointers: req.init.pointers,
    }),
    `origin ${req.init.origin}`,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: `tab ${op} failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; values: Record<string, string> }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op,
      values: resp.values,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: resp.error,
    });
  }
}
