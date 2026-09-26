/**
 * #418: capabilities this browser cannot serve, and how both halves of the
 * bridge talk about them.
 *
 * The extension finds, by runtime API detection, that some declared
 * capabilities cannot work here (Safari has no `chrome.downloads`, for one).
 * Before #418 its only move was to refuse the whole hello. Now it can grant the
 * servable subset and TELL the MCP which ones are missing, in three additive
 * places inside protocol 4:
 *
 * 1. `HelloFrameFromExtension.unavailableCapabilities` — sent only when
 *    non-empty, so a browser missing nothing puts the same bytes on the wire
 *    as before. Unsigned and advisory: see docs/SECURITY.md §T-unavailable-caps.
 * 2. `InnerResponseError.code === 'capability_unavailable'` plus the fixed
 *    wording from {@link capabilityUnavailableMessage}, on a request for one.
 * 3. The `unsupported-capability:` `hello-rejected` reason, kept for when
 *    NOTHING the MCP declared is servable.
 *
 * Nothing here feeds trust, pinning, the pair code, key derivation or a grant.
 */
import type { Capability } from './frames.js';

/** `InnerResponseError.code` for a request whose capability this browser lacks. */
export const CAPABILITY_UNAVAILABLE_CODE = 'capability_unavailable' as const;

/** Upper bound the validator puts on `unavailableCapabilities`. */
export const MAX_UNAVAILABLE_CAPABILITIES = 32;

/** Bounds on one entry's length, in UTF-16 code units. */
export const MAX_CAPABILITY_NAME_LENGTH = 64;

/**
 * Prefix of the `hello-rejected` reason sent when EVERY declared capability is
 * unavailable in this browser. The full reason is
 * `unsupported-capability: a, b (not available in this browser)` — sorted,
 * comma-and-space separated — and is a documented contract (PROTOCOL.md),
 * because `HelloRejectedFrame` is rebuilt field-by-field by every published
 * validator and so cannot carry a new field.
 */
export const UNSUPPORTED_CAPABILITY_REASON_PREFIX = 'unsupported-capability:';

/**
 * The fixed error text for a request whose capability this browser lacks.
 *
 * It must never contain "not granted": every published server classifies
 * `/^capability .+ not granted/` as `capability_denied` — a programmer error
 * in the MCP — and this is the browser's fault, not the MCP's.
 */
export function capabilityUnavailableMessage(capability: string, platform: string): string {
  return `capability ${JSON.stringify(capability)} is not available in this browser (${platform})`;
}

const UNAVAILABLE_RE =
  /^capability "([^"]{1,64})" is not available in this browser(?: \(([^)]{1,32})\))?/;

/**
 * Parse {@link capabilityUnavailableMessage}'s wording back out. Also accepts
 * the bridge's pre-#418 wording, which named no browser (`platform: null`).
 */
export function parseCapabilityUnavailable(
  error: string,
): { capability: string; platform: string | null } | null {
  const m = UNAVAILABLE_RE.exec(error);
  if (!m) return null;
  return { capability: m[1]!, platform: m[2] ?? null };
}

/**
 * The capability list out of an `unsupported-capability:` reason, or `null`
 * when the reason is something else.
 */
export function parseUnsupportedCapabilityReason(reason: string): string[] | null {
  if (!reason.startsWith(UNSUPPORTED_CAPABILITY_REASON_PREFIX)) return null;
  const rest = reason
    .slice(UNSUPPORTED_CAPABILITY_REASON_PREFIX.length)
    .replace(/\s*\(not available in this browser\)\s*$/, '')
    .trim();
  if (rest === '') return [];
  return rest
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * What the extension spreads into its hello: `{}` for an empty list, so the
 * wire of a browser that can serve everything is unchanged byte for byte, and
 * otherwise the list sorted and de-duplicated.
 */
export function unavailableCapabilitiesHelloField(caps: Iterable<Capability>): {
  unavailableCapabilities?: Capability[];
} {
  const list = [...new Set(caps)].sort();
  return list.length === 0 ? {} : { unavailableCapabilities: list };
}
