import {
  KNOWN_CAPABILITIES,
  type Capability,
  type HelloFrameFromExtension,
  type InnerFrame,
  type Platform,
} from '@fetchproxy/protocol';

/**
 * #418: what this MCP knows about the browser behind its CURRENT session —
 * taken from the extension hello whose `sessionNonce` the accepted `ready`
 * was verified against, never from whichever hello arrived last, and dropped
 * with the session.
 *
 * `unavailableCapabilities` is advisory (the extension hello is unsigned — see
 * docs/SECURITY.md §T-unavailable-caps): it only ever makes this MCP refuse a
 * verb locally. It must never feed trust, pinning, the pair code, key
 * derivation or a grant.
 */
export interface ExtensionSessionInfo {
  platform: Platform;
  /** Known capability names only, sorted and de-duplicated. */
  unavailableCapabilities: Capability[];
}

export function sessionInfoFromHello(hello: HelloFrameFromExtension): ExtensionSessionInfo {
  const raw: unknown = hello.unavailableCapabilities;
  const known = new Set<Capability>();
  if (Array.isArray(raw)) {
    for (const c of raw) {
      if (typeof c === 'string' && KNOWN_CAPABILITIES.has(c as Capability))
        known.add(c as Capability);
    }
  }
  return { platform: hello.platform, unavailableCapabilities: [...known].sort() };
}

/**
 * The capabilities an outbound request needs. Every op names its own
 * capability except `graphql_query` (governed by `graphql`); a fetch marked
 * `inPage` additionally needs `fetch_in_page`.
 */
export function capabilitiesForRequest(inner: InnerFrame): Capability[] {
  if (inner.type !== 'request') return [];
  if (inner.op === 'graphql_query') return ['graphql'];
  if (inner.op === 'fetch') {
    return inner.init.inPage === true ? ['fetch', 'fetch_in_page'] : ['fetch'];
  }
  return [inner.op as Capability];
}

/** The first capability `inner` needs that the session says is unavailable, or null. */
export function unavailableCapabilityFor(
  inner: InnerFrame,
  info: ExtensionSessionInfo | null,
): Capability | null {
  if (!info || info.unavailableCapabilities.length === 0) return null;
  for (const c of capabilitiesForRequest(inner)) {
    if (info.unavailableCapabilities.includes(c)) return c;
  }
  return null;
}
