/**
 * WS frame types for the fetchproxy protocol. JSON-over-WS, one verb
 * (`fetch`) plus lifecycle frames. See docs/PROTOCOL.md for semantics.
 */

export type Platform = 'chrome' | 'safari' | 'firefox';

/** Extension → Server. Sent immediately after connection. */
export interface HelloExtension {
  type: 'hello';
  role: 'extension';
  version: string;
  platform: Platform;
  extension_id: string;
}

/** Server → Extension. Sent in response to the extension's hello. */
export interface HelloServer {
  type: 'hello';
  role: 'server';
  server: string;
  version: string;
  /** Domain this MCP is allowed to fetch from. The extension enforces
   *  this as an allowlist on every fetch request. */
  domain: string;
}

export type Hello = HelloExtension | HelloServer;

/** Extension → Server. Sent when the extension has at least one tab
 *  matching the server's `domain`. */
export interface Ready {
  type: 'ready';
}

export interface Ping {
  type: 'ping';
}

export interface Pong {
  type: 'pong';
}

/** Server → Extension. */
export interface FetchRequest {
  type: 'request';
  id: number;
  op: 'fetch';
  init: FetchInit;
}

export interface FetchInit {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  /** Prefix-matched against open tab URLs; first match wins. */
  tabUrl: string;
}

/** Extension → Server. */
export interface FetchResponseOk {
  type: 'response';
  id: number;
  ok: true;
  status: number;
  url: string;
  body: string;
}

export interface FetchResponseErr {
  type: 'response';
  id: number;
  ok: false;
  error: string;
}

export type FetchResponse = FetchResponseOk | FetchResponseErr;

export type Frame =
  | Hello
  | Ready
  | Ping
  | Pong
  | FetchRequest
  | FetchResponse;
