/**
 * What the BROWSER user is told when a version mismatch is refused at the
 * hello (Task 4.3 of protocol v4).
 *
 * Task 4.1 gave the MCP an answer on the wire — `hello-rejected`, naming both
 * versions — and gave the person sitting in front of the browser nothing but a
 * `console.warn` in a service worker nobody has open. That side matters on its
 * own, and not only for symmetry: an MCP older than 2.6.0 cannot hear
 * `hello-rejected` at all, and a refused MCP is never trusted, never gets a
 * session and never lights a status dot — so every surface the popup already
 * had renders this failure as ABSENCE, which is indistinguishable from "no MCP
 * is running". The line below is the one place that says otherwise.
 *
 * The record is written by the refusal path (`background/socket.ts`) and read
 * by the popup, which is a different context and a different process lifetime,
 * so it lives in `chrome.storage.local` rather than in `state`. Everything
 * here is pure over that value; the storage calls are the callers'.
 *
 * **Nothing here is trusted input.** Every field originates in a hello no
 * validator accepted, so `serverName` is attacker-chosen text (`[^:]+` out of
 * an `mcpId`) and is length-capped here and rendered with `textContent` there.
 * `peekHelloVersion` deliberately drops the hello's own `serverName` field for
 * this reason; the name below is parsed out of the `mcpId` that peek DID
 * validate, so it is bounded in shape as well as in length.
 */

export const VERSION_MISMATCH_KEY = 'versionMismatch';

/**
 * The `@fetchproxy/server` version at which protocol 4 lands — the same fact
 * `socket.ts` states on the wire, in one place so the two cannot drift. A
 * literal rather than a derived value: this extension cannot read the MCP's
 * package version, and the number it prints is a fact about the cohort
 * release, not about this build.
 */
export const MIN_SERVER_VERSION = '3.0.0';

/**
 * How long a refusal keeps accusing. A refused MCP that is then switched off
 * for good leaves a record nothing will ever clear — the clear below hangs off
 * a SUCCESSFUL hello, which by definition never arrives — and a popup that
 * keeps naming a server the user retired a month ago is a surface people learn
 * to ignore. A day is long enough to survive an overnight, short enough that
 * the line is always about something current.
 */
export const VERSION_MISMATCH_TTL_MS = 24 * 60 * 60 * 1000;

/** Beyond this many, the oldest are dropped: the popup is not a log. */
const MAX_ENTRIES = 8;

/** `serverName` is attacker-chosen; the popup is 360px wide. */
const MAX_NAME_LEN = 64;

/** One refused hello, as the popup needs to describe it. */
export interface VersionMismatch {
  /** The bridge link it arrived on (`local`, or `remote:<id>`). */
  linkId: string;
  /** That link's human label, for the line's tooltip. */
  linkLabel: string;
  /** Parsed out of the `mcpId`, never read off the refused frame's own field. */
  serverName: string;
  /** The protocol version the MCP announced. */
  mcpProtocol: number;
  /** The protocol version this extension speaks. */
  extensionProtocol: number;
  /** When it was refused (epoch ms), for the TTL above. */
  at: number;
}

/**
 * The dict key: one entry per (link, server NAME).
 *
 * Not per link, because the loopback concentrator multiplexes every MCP on the
 * machine and one upgraded server would hide a stale neighbour. Not per
 * `mcpId`, because the `mcpId` carries a fresh 16-hex block per process, so an
 * MCP that is restarted — which is exactly what upgrading it involves — would
 * never clear the line it left behind, and a restart loop would fill the popup
 * with a line per attempt.
 */
function keyOf(linkId: string, serverName: string): string {
  return `${linkId}\u0000${serverName}`;
}

/**
 * Rebuild the stored value member by member, dropping anything malformed — the
 * `readEnvelope` / `normalisePendingPair` pattern. The popup and the
 * background read the same key, so they have to agree on what counts as a
 * record, and a shape written by a future version must not reach the DOM
 * because it happened to be in storage.
 */
export function normaliseVersionMismatches(stored: unknown): Record<string, VersionMismatch> {
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) return {};
  const out: Record<string, VersionMismatch> = {};
  for (const v of Object.values(stored as Record<string, unknown>)) {
    if (!v || typeof v !== 'object') continue;
    const r = v as Record<string, unknown>;
    if (typeof r.linkId !== 'string' || r.linkId === '') continue;
    if (typeof r.serverName !== 'string' || r.serverName === '') continue;
    if (typeof r.mcpProtocol !== 'number' || !Number.isInteger(r.mcpProtocol)) continue;
    if (typeof r.extensionProtocol !== 'number' || !Number.isInteger(r.extensionProtocol)) continue;
    if (typeof r.at !== 'number' || !Number.isFinite(r.at)) continue;
    const rec: VersionMismatch = {
      linkId: r.linkId,
      linkLabel: typeof r.linkLabel === 'string' ? r.linkLabel.slice(0, MAX_NAME_LEN) : r.linkId,
      serverName: r.serverName.slice(0, MAX_NAME_LEN),
      mcpProtocol: r.mcpProtocol,
      extensionProtocol: r.extensionProtocol,
      at: r.at,
    };
    out[keyOf(rec.linkId, rec.serverName)] = rec;
  }
  return out;
}

/** Add one refusal, newest wins, oldest dropped past {@link MAX_ENTRIES}. */
export function recordVersionMismatch(
  dict: Record<string, VersionMismatch>,
  m: VersionMismatch,
): Record<string, VersionMismatch> {
  const rec: VersionMismatch = { ...m, serverName: m.serverName.slice(0, MAX_NAME_LEN) };
  const next = { ...dict, [keyOf(rec.linkId, rec.serverName)]: rec };
  const entries = Object.entries(next).sort((a, b) => b[1].at - a[1].at);
  return Object.fromEntries(entries.slice(0, MAX_ENTRIES));
}

/**
 * Forget the refusals a successful v4 hello refutes: this server, on this
 * link. The hello passing `validateFrame` IS the proof — `protocolVersion`
 * must equal `PROTOCOL_VERSION` to get that far — so the clear hangs off the
 * hello rather than off the session it may or may not go on to establish. A
 * hello that is v4 and then fails on trust or on a signature is a different
 * complaint with its own surfaces, and leaving a VERSION line up for it would
 * be the popup saying something untrue.
 */
export function clearVersionMismatches(
  dict: Record<string, VersionMismatch>,
  linkId: string,
  serverName: string,
): Record<string, VersionMismatch> {
  const k = keyOf(linkId, serverName.slice(0, MAX_NAME_LEN));
  if (!(k in dict)) return dict;
  const next = { ...dict };
  delete next[k];
  return next;
}

/** The records still worth showing at `now` — see {@link VERSION_MISMATCH_TTL_MS}. */
export function freshVersionMismatches(
  dict: Record<string, VersionMismatch>,
  now: number,
): Record<string, VersionMismatch> {
  const out: Record<string, VersionMismatch> = {};
  for (const [k, v] of Object.entries(dict)) {
    if (now - v.at < VERSION_MISMATCH_TTL_MS) out[k] = v;
  }
  return out;
}

/**
 * The sentence the popup shows, in one place so the wording is asserted once.
 *
 * It names the server and BOTH versions, because a refusal naming one version
 * is not a diagnosis — the reader cannot tell which end is behind. It ends by
 * putting the remedy where the remedy is: this browser cannot fix it, and an
 * instruction the reader can only fail to carry out is worse than none. What
 * they CAN do with this line is tell whoever runs the MCP, which needs the
 * server's name and the number to upgrade to — both of which are in it.
 */
export function versionMismatchLine(m: VersionMismatch): string {
  return (
    `${m.serverName} was refused: it speaks fetchproxy protocol ${m.mcpProtocol}, ` +
    `this extension speaks ${m.extensionProtocol}. ` +
    `Update that MCP to @fetchproxy/server ${MIN_SERVER_VERSION} or later — ` +
    `nothing in this browser fixes it.`
  );
}
