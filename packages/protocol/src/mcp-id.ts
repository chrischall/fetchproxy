const ID_RE = /^([^:]+):([^:]+):([0-9a-f]{16})$/;

export interface McpIdParts {
  serverName: string;
  version: string;
  rand: string;
}

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

export function parseMcpId(id: string): McpIdParts {
  const m = ID_RE.exec(id);
  if (!m || !m[1] || !m[2] || !m[3]) {
    throw new Error(`invalid mcpId: ${id}`);
  }
  return { serverName: m[1], version: m[2], rand: m[3] };
}

export function isValidMcpId(id: unknown): id is string {
  return typeof id === 'string' && ID_RE.test(id);
}

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  (globalThis.crypto as Crypto).getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}
