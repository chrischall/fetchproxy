/**
 * `mcpId` format: `<serverName>:<version>:<16-hex-rand>`. The trailing
 * 16-hex-char block disambiguates two restarts of the same server,
 * which the extension uses to detect "same identity, fresh process".
 */
const ID_RE = /^([^:]+):([^:]+):([0-9a-f]{16})$/;

/** Parsed components of an `mcpId`. */
export interface McpIdParts {
  serverName: string;
  version: string;
  rand: string;
}

/**
 * Build a fresh `mcpId` from a server name + version. The trailing
 * random block is 64 bits drawn from `crypto.getRandomValues`; collisions
 * with a previous restart are negligible. Throws if either input
 * contains a literal `:` (would corrupt the wire format).
 */
export function generateMcpId(serverName: string, version: string): string {
  if (serverName.includes(':')) {
    throw new Error(`serverName cannot contain ':': ${serverName}`);
  }
  if (version.includes(':')) {
    throw new Error(`version cannot contain ':': ${version}`);
  }
  const rand = randomHex(8); // 16 hex chars
  return `${serverName}:${version}:${rand}`;
}

/** Parse an `mcpId` into its three components. Throws on malformed input. */
export function parseMcpId(id: string): McpIdParts {
  const m = ID_RE.exec(id);
  if (!m || !m[1] || !m[2] || !m[3]) {
    throw new Error(`invalid mcpId: ${id}`);
  }
  return { serverName: m[1], version: m[2], rand: m[3] };
}

/** Type-guard for the `mcpId` wire format. Used by the protocol validator. */
export function isValidMcpId(id: unknown): id is string {
  return typeof id === 'string' && ID_RE.test(id);
}

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  (globalThis.crypto as Crypto).getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}
