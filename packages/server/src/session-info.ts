import {
  EXTENSION_FEATURE_FETCH_BASE64,
  KNOWN_CAPABILITIES,
  KNOWN_EXTENSION_FEATURES,
  type ExtensionFeature,
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
  /**
   * #460: the hello's `features`, known names only, sorted and de-duplicated.
   * Advisory like `unavailableCapabilities`: it only ever makes this MCP
   * refuse a request locally. What a binary answer is TRUSTED on is its own
   * `bodyEncoding` marker, never this list.
   */
  features: ExtensionFeature[];
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
  const features = new Set<ExtensionFeature>();
  const rawFeatures: unknown = hello.features;
  if (Array.isArray(rawFeatures)) {
    for (const f of rawFeatures) {
      if (typeof f === 'string' && KNOWN_EXTENSION_FEATURES.has(f as ExtensionFeature))
        features.add(f as ExtensionFeature);
    }
  }
  return {
    platform: hello.platform,
    unavailableCapabilities: [...known].sort(),
    features: [...features].sort(),
  };
}

/**
 * #460: the extension feature an outbound request needs, or null. Today one:
 * a `fetch` asking for `responseType: 'base64'` needs `fetch_base64`.
 */
export function featureForRequest(inner: InnerFrame): ExtensionFeature | null {
  if (inner.type !== 'request' || inner.op !== 'fetch') return null;
  return inner.init.responseType === 'base64' ? EXTENSION_FEATURE_FETCH_BASE64 : null;
}

/**
 * #460: the feature `inner` needs that the session's extension did NOT list,
 * or null. `info === null` (no hello to judge — a peer behind a host too old
 * to relay it) returns null: the request goes out and the answer's own
 * `bodyEncoding` marker decides.
 */
export function missingFeatureFor(
  inner: InnerFrame,
  info: ExtensionSessionInfo | null,
): ExtensionFeature | null {
  const feature = featureForRequest(inner);
  if (feature === null || info === null) return null;
  return info.features.includes(feature) ? null : feature;
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
