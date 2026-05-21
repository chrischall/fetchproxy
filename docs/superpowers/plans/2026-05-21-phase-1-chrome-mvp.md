# Phase 1 — Chrome MVP + @fetchproxy/server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the new fetchproxy repo to feature-parity with opentable-mcp's embedded extension, plus the new security primitives (trust prompt, per-MCP domain allowlist), then migrate opentable-mcp to depend on `@fetchproxy/server`.

**Architecture:** Four npm workspace packages: `@fetchproxy/protocol` (shared types + frame validators), `@fetchproxy/server` (Node WS server library MCPs depend on), `extension-core` (TypeScript shared between browser packages), `extension-chrome` (Chrome MV3 packaging). Each task lands as a single commit; tests stay green throughout. The opentable-mcp migration is the last step — old extension keeps working until the new one is verified.

**Tech Stack:** TypeScript, npm workspaces, vitest, esbuild, Chrome Manifest V3.

**Spec:** [`README.md`](../../../README.md), [`docs/PROTOCOL.md`](../../PROTOCOL.md), [`docs/SECURITY.md`](../../SECURITY.md).

---

## File Structure

```
fetchproxy/
├── package.json                     (workspaces root)
├── tsconfig.base.json
├── .prettierrc
├── packages/
│   ├── protocol/                    (npm: @fetchproxy/protocol)
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── src/
│   │   │   ├── index.ts             (re-exports)
│   │   │   ├── frames.ts            (Hello, Ready, Ping, Pong, Request, Response)
│   │   │   └── validate.ts          (runtime schema validation)
│   │   └── tests/
│   │       └── validate.test.ts
│   ├── server/                      (npm: @fetchproxy/server)
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── src/
│   │   │   ├── index.ts             (FetchproxyServer public API)
│   │   │   └── ws-server.ts         (WS server impl)
│   │   └── tests/
│   │       └── ws-server.test.ts
│   ├── extension-core/              (private)
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── src/
│   │   │   ├── background.ts        (service worker entry)
│   │   │   ├── content.ts           (content script entry)
│   │   │   ├── trust-store.ts       (chrome.storage trusted-MCP CRUD)
│   │   │   ├── lib/
│   │   │   │   ├── url-match.ts     (domain allowlist check)
│   │   │   │   └── frame-handler.ts (parse + validate WS frames)
│   │   │   └── popup/
│   │   │       ├── popup.html
│   │   │       └── popup.ts
│   │   └── tests/
│   │       ├── url-match.test.ts
│   │       ├── frame-handler.test.ts
│   │       └── trust-store.test.ts
│   └── extension-chrome/            (private)
│       ├── package.json
│       ├── manifest.json
│       ├── icons/{16,48,128}.png    (placeholder; we'll iterate)
│       └── build.ts                 (esbuild script → dist/)
├── README.md                        (already exists)
├── LICENSE                          (already exists)
└── docs/
    ├── PROTOCOL.md                  (already exists)
    └── SECURITY.md                  (already exists)
```

Twelve tasks. Each is a self-contained commit; the repo stays buildable + tests-green between tasks. The opentable-mcp migration is the second-to-last task and only runs after the rest is verified.

---

### Task 0: npm workspaces scaffold + tooling

**Files:**
- Create: `package.json` (workspaces root)
- Create: `tsconfig.base.json`
- Create: `.prettierrc`
- Modify: `.gitignore` (add workspace dist dirs)

Set up the monorepo so subsequent tasks can `npm install` + `npm run build` predictably.

- [ ] **Step 1: Write root `package.json`**

```json
{
  "name": "fetchproxy",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "workspaces": [
    "packages/*"
  ],
  "scripts": {
    "build": "npm run build --workspaces --if-present",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit --build packages/*"
  },
  "devDependencies": {
    "@types/node": "^25.5.2",
    "prettier": "^3.3.0",
    "typescript": "^6.0.0",
    "vitest": "^4.1.0"
  }
}
```

- [ ] **Step 2: Write `tsconfig.base.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "verbatimModuleSyntax": true,
    "declaration": true,
    "sourceMap": true
  }
}
```

- [ ] **Step 3: Write `.prettierrc`**

```json
{
  "singleQuote": true,
  "semi": true,
  "trailingComma": "all",
  "printWidth": 100
}
```

- [ ] **Step 4: Install**

```bash
npm install
```

Expected: completes without error. `node_modules/` populated.

- [ ] **Step 5: Commit**

```bash
git add package.json tsconfig.base.json .prettierrc package-lock.json
git commit -m "chore: npm workspaces + tsconfig base + prettier

Sets up the monorepo skeleton. Per-package package.json + tsconfig.json
land in their respective tasks. typecheck and test scripts will hook
into per-package configs as they're added.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 1: `@fetchproxy/protocol` — frame types + validators

**Files:**
- Create: `packages/protocol/package.json`
- Create: `packages/protocol/tsconfig.json`
- Create: `packages/protocol/src/index.ts`
- Create: `packages/protocol/src/frames.ts`
- Create: `packages/protocol/src/validate.ts`
- Create: `packages/protocol/tests/validate.test.ts`

Shared TypeScript types for the WS protocol. Both `@fetchproxy/server` and `extension-core` import from here. Validators are defensive — runtime schema checks on every incoming frame.

- [ ] **Step 1: Write the failing test**

`packages/protocol/tests/validate.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { validateFrame, ProtocolError } from '../src/validate.js';

describe('validateFrame', () => {
  it('accepts a valid hello (server) frame', () => {
    const frame = {
      type: 'hello',
      role: 'server',
      server: 'opentable-mcp',
      version: '0.9.1',
      domain: 'opentable.com',
    };
    expect(() => validateFrame(frame)).not.toThrow();
    expect(validateFrame(frame).type).toBe('hello');
  });

  it('accepts a valid hello (extension) frame', () => {
    const frame = {
      type: 'hello',
      role: 'extension',
      version: '1.0.0',
      platform: 'chrome',
      extension_id: 'fetchproxy',
    };
    expect(() => validateFrame(frame)).not.toThrow();
  });

  it('accepts a valid request/fetch frame', () => {
    const frame = {
      type: 'request',
      id: 1,
      op: 'fetch',
      init: {
        url: 'https://www.opentable.com/x',
        method: 'GET',
        tabUrl: 'https://www.opentable.com/',
      },
    };
    expect(() => validateFrame(frame)).not.toThrow();
  });

  it('rejects unknown frame type', () => {
    expect(() => validateFrame({ type: 'mystery' })).toThrow(ProtocolError);
  });

  it('rejects request frame with non-integer id', () => {
    const frame = {
      type: 'request',
      id: 'one',
      op: 'fetch',
      init: { url: 'https://x', method: 'GET', tabUrl: 'https://x/' },
    };
    expect(() => validateFrame(frame)).toThrow(/id/);
  });

  it('rejects request frame with non-https url', () => {
    const frame = {
      type: 'request',
      id: 1,
      op: 'fetch',
      init: { url: 'javascript:alert(1)', method: 'GET', tabUrl: 'https://x/' },
    };
    expect(() => validateFrame(frame)).toThrow(/url/);
  });

  it('rejects prototype-pollution keys', () => {
    expect(() => validateFrame({ type: 'ping', __proto__: {} })).toThrow();
    expect(() => validateFrame({ type: 'ping', constructor: {} })).toThrow();
  });

  it('rejects non-object input', () => {
    expect(() => validateFrame('hello')).toThrow();
    expect(() => validateFrame(null)).toThrow();
    expect(() => validateFrame(42)).toThrow();
  });
});
```

- [ ] **Step 2: Write `packages/protocol/package.json`**

```json
{
  "name": "@fetchproxy/protocol",
  "version": "0.0.1",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsc -b"
  }
}
```

- [ ] **Step 3: Write `packages/protocol/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src",
    "composite": true
  },
  "include": ["src/**/*"]
}
```

- [ ] **Step 4: Write `packages/protocol/src/frames.ts`**

```typescript
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
```

- [ ] **Step 5: Write `packages/protocol/src/validate.ts`**

```typescript
/**
 * Runtime schema validation for incoming WS frames. Defensive against
 * malformed input (prototype pollution, wrong types, unknown frame
 * types). Throws ProtocolError on invalid input; callers should close
 * the WS with code 1002.
 */
import type { Frame } from './frames.js';

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function assertObject(x: unknown): asserts x is Record<string, unknown> {
  if (x === null || typeof x !== 'object' || Array.isArray(x)) {
    throw new ProtocolError(`expected object, got ${typeof x}`);
  }
  for (const k of Object.keys(x)) {
    if (FORBIDDEN_KEYS.has(k)) {
      throw new ProtocolError(`forbidden key: ${k}`);
    }
  }
}

function assertString(x: unknown, field: string): asserts x is string {
  if (typeof x !== 'string') {
    throw new ProtocolError(`expected string for ${field}, got ${typeof x}`);
  }
}

function assertInteger(x: unknown, field: string): asserts x is number {
  if (typeof x !== 'number' || !Number.isInteger(x)) {
    throw new ProtocolError(`expected integer for ${field}, got ${typeof x}`);
  }
}

function assertHttpUrl(x: unknown, field: string): asserts x is string {
  assertString(x, field);
  try {
    const u = new URL(x);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') {
      throw new ProtocolError(`${field} must be http(s), got ${u.protocol}`);
    }
  } catch (e) {
    if (e instanceof ProtocolError) throw e;
    throw new ProtocolError(`${field} is not a valid URL: ${String(x).slice(0, 80)}`);
  }
}

/** Validate an incoming frame. Returns the same value (narrowed) on
 *  success; throws ProtocolError on any malformation. */
export function validateFrame(raw: unknown): Frame {
  assertObject(raw);
  assertString(raw.type, 'type');
  switch (raw.type) {
    case 'hello': {
      assertString(raw.role, 'role');
      if (raw.role === 'extension') {
        assertString(raw.version, 'version');
        assertString(raw.platform, 'platform');
        assertString(raw.extension_id, 'extension_id');
        return raw as unknown as Frame;
      }
      if (raw.role === 'server') {
        assertString(raw.server, 'server');
        assertString(raw.version, 'version');
        assertString(raw.domain, 'domain');
        return raw as unknown as Frame;
      }
      throw new ProtocolError(`unknown hello role: ${raw.role}`);
    }
    case 'ready':
    case 'ping':
    case 'pong':
      return raw as unknown as Frame;
    case 'request': {
      assertInteger(raw.id, 'id');
      assertString(raw.op, 'op');
      if (raw.op !== 'fetch') {
        throw new ProtocolError(`unknown op: ${raw.op}`);
      }
      assertObject(raw.init);
      assertHttpUrl(raw.init.url, 'init.url');
      assertString(raw.init.method, 'init.method');
      assertString(raw.init.tabUrl, 'init.tabUrl');
      return raw as unknown as Frame;
    }
    case 'response': {
      assertInteger(raw.id, 'id');
      if (raw.ok === true) {
        assertInteger(raw.status, 'status');
        assertString(raw.url, 'url');
        assertString(raw.body, 'body');
        return raw as unknown as Frame;
      }
      if (raw.ok === false) {
        assertString(raw.error, 'error');
        return raw as unknown as Frame;
      }
      throw new ProtocolError(`response.ok must be boolean, got ${typeof raw.ok}`);
    }
    default:
      throw new ProtocolError(`unknown frame type: ${raw.type}`);
  }
}
```

- [ ] **Step 6: Write `packages/protocol/src/index.ts`**

```typescript
export * from './frames.js';
export { validateFrame, ProtocolError } from './validate.js';
```

- [ ] **Step 7: Run tests + build**

```bash
npm test -- protocol
npm run build --workspace @fetchproxy/protocol
```

Expected: tests pass. `packages/protocol/dist/` populated.

- [ ] **Step 8: Commit**

```bash
git add packages/protocol package-lock.json
git commit -m "@fetchproxy/protocol: frame types + runtime validators

Shared TypeScript types for the WS protocol (Hello, Ready, Ping, Pong,
Request, Response) plus a defensive runtime validator. Validator
rejects: non-objects, prototype-pollution keys (__proto__, constructor,
prototype), unknown frame types, non-http(s) URLs, non-integer ids.

Throws ProtocolError on malformation; callers close the WS with code
1002 (protocol error). Defends against T6 in the threat model
(service worker compromise via crafted frame).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `@fetchproxy/server` — Node WS library

**Files:**
- Create: `packages/server/package.json`
- Create: `packages/server/tsconfig.json`
- Create: `packages/server/src/index.ts`
- Create: `packages/server/src/ws-server.ts`
- Create: `packages/server/tests/ws-server.test.ts`

Port `opentable-mcp/src/ws-server.ts` into a domain-agnostic library. Constructor takes `{ port, server, version, domain }` and sends those in the `hello` frame. The library handles connection lifecycle, request/response correlation, timeouts, and pings.

- [ ] **Step 1: Write the failing test**

`packages/server/tests/ws-server.test.ts`:

```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { FetchproxyServer } from '../src/index.js';

const TEST_PORT = 47149;

describe('FetchproxyServer', () => {
  let server: FetchproxyServer;

  beforeEach(async () => {
    server = new FetchproxyServer({
      port: TEST_PORT,
      server: 'test-mcp',
      version: '0.0.1',
      domain: 'example.com',
    });
    await server.start();
  });

  afterEach(async () => {
    await server.close();
  });

  it('sends a hello frame to the extension when it connects', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`);
    const helloFromServer = await new Promise<unknown>((resolve) => {
      ws.on('message', (data) => resolve(JSON.parse(String(data))));
    });
    expect(helloFromServer).toMatchObject({
      type: 'hello',
      role: 'server',
      server: 'test-mcp',
      version: '0.0.1',
      domain: 'example.com',
    });
    ws.close();
  });

  it('relays a fetch through the extension', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`);
    ws.on('open', () => {
      ws.send(JSON.stringify({
        type: 'hello',
        role: 'extension',
        version: '1.0.0',
        platform: 'chrome',
        extension_id: 'fetchproxy',
      }));
      ws.send(JSON.stringify({ type: 'ready' }));
    });
    // Echo any request back as a successful response.
    ws.on('message', (data) => {
      const frame = JSON.parse(String(data));
      if (frame.type === 'request') {
        ws.send(JSON.stringify({
          type: 'response',
          id: frame.id,
          ok: true,
          status: 200,
          url: frame.init.url,
          body: 'echo',
        }));
      }
    });

    const result = await server.fetch({
      url: 'https://example.com/foo',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    expect(result.status).toBe(200);
    expect(result.body).toBe('echo');
    ws.close();
  });

  it('throws "extension offline" if no extension is connected within the timeout', async () => {
    server.setConnectTimeoutMs(100);
    await expect(
      server.fetch({
        url: 'https://example.com/foo',
        method: 'GET',
        tabUrl: 'https://example.com/',
      })
    ).rejects.toThrow(/extension offline/);
  });

  it('rejects a second simultaneous extension connection', async () => {
    const ws1 = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`);
    await new Promise<void>((resolve) => ws1.on('open', resolve));
    const ws2 = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`);
    const closeReason = await new Promise<string>((resolve) => {
      ws2.on('close', (_code, reason) => resolve(reason.toString()));
    });
    expect(closeReason).toMatch(/already connected/i);
    ws1.close();
  });

  it('rejects WS upgrades whose Origin is a public web origin', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`, {
      headers: { Origin: 'https://evil.example.com' },
    });
    const closed = await new Promise<boolean>((resolve) => {
      ws.on('close', () => resolve(true));
      ws.on('error', () => resolve(true));
    });
    expect(closed).toBe(true);
  });
});
```

- [ ] **Step 2: Write `packages/server/package.json`**

```json
{
  "name": "@fetchproxy/server",
  "version": "0.0.1",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsc -b"
  },
  "dependencies": {
    "@fetchproxy/protocol": "*",
    "ws": "^8.20.0"
  },
  "devDependencies": {
    "@types/ws": "^8.18.0"
  }
}
```

- [ ] **Step 3: Write `packages/server/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src",
    "composite": true
  },
  "include": ["src/**/*"],
  "references": [{ "path": "../protocol" }]
}
```

- [ ] **Step 4: Write `packages/server/src/ws-server.ts`**

```typescript
/**
 * FetchproxyServer: the localhost WebSocket bridge an MCP server uses
 * to relay fetches through the user's signed-in browser. Domain-agnostic
 * port of opentable-mcp's OpenTableWsServer.
 *
 * One extension at a time. Connect-timeout for "extension offline"
 * detection (default 15s). Per-request timeout (default 30s).
 * 20s ping to keep the MV3 service worker warm.
 */
import { WebSocketServer, WebSocket } from 'ws';
import { validateFrame, type Frame, type FetchInit, type FetchResponse } from '@fetchproxy/protocol';

const PING_INTERVAL_MS = 20_000;
const MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024; // 5 MB
const PUBLIC_ORIGIN_REGEX = /^https?:\/\/(?!(127\.0\.0\.1|localhost)(:|$))/i;

export interface FetchproxyServerOptions {
  port: number;
  /** MCP server name announced in `hello`. */
  server: string;
  /** MCP server version (semver). */
  version: string;
  /** Allowed domain for fetch destinations. The extension enforces this. */
  domain: string;
}

export interface FetchResult {
  status: number;
  body: string;
  url: string;
}

interface PendingRequest {
  resolve: (v: FetchResult) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

export class FetchproxyServer {
  private readonly opts: FetchproxyServerOptions;
  private wss: WebSocketServer | null = null;
  private active: WebSocket | null = null;
  private nextId = 1;
  private pending = new Map<number, PendingRequest>();
  private pingTimer: NodeJS.Timeout | null = null;
  private connectTimeoutMs = 15_000;
  private requestTimeoutMs = 30_000;
  private readyResolvers: Array<() => void> = [];

  constructor(opts: FetchproxyServerOptions) {
    this.opts = opts;
  }

  setConnectTimeoutMs(ms: number): void {
    this.connectTimeoutMs = ms;
  }

  setRequestTimeoutMs(ms: number): void {
    this.requestTimeoutMs = ms;
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.wss = new WebSocketServer({
        host: '127.0.0.1',
        port: this.opts.port,
        verifyClient: (info, cb) => {
          // Reject upgrades from public web origins (defense T2).
          const origin = info.req.headers.origin;
          if (origin && PUBLIC_ORIGIN_REGEX.test(origin)) {
            cb(false, 403, 'Forbidden origin');
            return;
          }
          cb(true);
        },
      });
      this.wss.on('listening', () => resolve());
      this.wss.on('error', reject);
      this.wss.on('connection', (ws) => this.handleConnection(ws));
    });
    this.pingTimer = setInterval(() => this.ping(), PING_INTERVAL_MS);
  }

  async close(): Promise<void> {
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.pingTimer = null;
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error('Server closing'));
    }
    this.pending.clear();
    if (this.active) this.active.close();
    this.active = null;
    await new Promise<void>((r) => {
      if (!this.wss) return r();
      this.wss.close(() => r());
    });
    this.wss = null;
  }

  /** Proxy a fetch through the extension. */
  async fetch(init: FetchInit): Promise<FetchResult> {
    await this.waitForConnection();
    if (!this.active) {
      throw new Error(`fetchproxy extension offline — install it and open a ${this.opts.domain} tab`);
    }
    const id = this.nextId++;
    return new Promise<FetchResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`fetchproxy request timed out after ${this.requestTimeoutMs}ms`));
      }, this.requestTimeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.active!.send(JSON.stringify({ type: 'request', id, op: 'fetch', init }));
    });
  }

  private handleConnection(ws: WebSocket): void {
    if (this.active && this.active.readyState === WebSocket.OPEN) {
      ws.close(1000, 'Another extension already connected');
      return;
    }
    this.active = ws;

    // Send our hello immediately.
    ws.send(JSON.stringify({
      type: 'hello',
      role: 'server',
      server: this.opts.server,
      version: this.opts.version,
      domain: this.opts.domain,
    }));

    ws.on('message', (raw) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(String(raw));
      } catch {
        ws.close(1002, 'invalid JSON');
        return;
      }
      let frame: Frame;
      try {
        frame = validateFrame(parsed);
      } catch (e) {
        ws.close(1002, `protocol error: ${(e as Error).message}`);
        return;
      }
      this.handleFrame(frame, ws);
    });

    ws.on('close', () => {
      if (this.active === ws) this.active = null;
      for (const [, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new Error('Extension disconnected during request'));
      }
      this.pending.clear();
    });
  }

  private handleFrame(frame: Frame, ws: WebSocket): void {
    switch (frame.type) {
      case 'hello':
        // Just an introduction; nothing to do server-side.
        return;
      case 'ready': {
        const waiters = this.readyResolvers.splice(0);
        for (const r of waiters) r();
        return;
      }
      case 'ping':
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      case 'pong':
        return;
      case 'response': {
        const pending = this.pending.get(frame.id);
        if (!pending) return;
        clearTimeout(pending.timer);
        this.pending.delete(frame.id);
        if (frame.ok) {
          if (frame.body.length > MAX_RESPONSE_BODY_BYTES) {
            pending.reject(new Error(`response body too large: ${frame.body.length} bytes`));
            return;
          }
          pending.resolve({ status: frame.status, body: frame.body, url: frame.url });
        } else {
          pending.reject(new Error(frame.error));
        }
        return;
      }
    }
  }

  private ping(): void {
    if (this.active && this.active.readyState === WebSocket.OPEN) {
      this.active.send(JSON.stringify({ type: 'ping' }));
    }
  }

  private waitForConnection(): Promise<void> {
    if (this.active && this.active.readyState === WebSocket.OPEN) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.readyResolvers.indexOf(resolve);
        if (idx >= 0) this.readyResolvers.splice(idx, 1);
        reject(new Error(`fetchproxy extension offline — install it and open a ${this.opts.domain} tab`));
      }, this.connectTimeoutMs);
      this.readyResolvers.push(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
}
```

- [ ] **Step 5: Write `packages/server/src/index.ts`**

```typescript
export { FetchproxyServer } from './ws-server.js';
export type {
  FetchproxyServerOptions,
  FetchResult,
} from './ws-server.js';
export type { FetchInit } from '@fetchproxy/protocol';
```

- [ ] **Step 6: Install ws + run tests**

```bash
npm install --workspace @fetchproxy/server
npm test -- server
npm run build --workspace @fetchproxy/server
```

Expected: 5 tests pass.

- [ ] **Step 7: Commit**

```bash
git add packages/server package-lock.json package.json
git commit -m "@fetchproxy/server: domain-agnostic WS server library

Port of opentable-mcp's OpenTableWsServer. Constructor takes
{ port, server, version, domain }; sends those in the hello frame
on every connection. Domain is what the extension uses to enforce
the per-MCP fetch allowlist.

Defenses implemented at this layer:
- WS binds 127.0.0.1 only
- verifyClient rejects upgrades with public Origin headers
- Every incoming frame goes through @fetchproxy/protocol's validateFrame
- Body size cap (5 MB); larger responses reject the pending request
- Invalid JSON or schema closes the WS with code 1002

One extension at a time; second connection gets closed with
\"Another extension already connected\".

5 unit tests cover: hello round-trip, fetch relay, connect-timeout,
duplicate-connection rejection, public-origin rejection.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `extension-core` skeleton + URL match helper

**Files:**
- Create: `packages/extension-core/package.json`
- Create: `packages/extension-core/tsconfig.json`
- Create: `packages/extension-core/src/lib/url-match.ts`
- Create: `packages/extension-core/tests/url-match.test.ts`

Pure helper: does this URL match this MCP's allowed domain? Tested in isolation so the runtime extension code stays small.

- [ ] **Step 1: Write the failing test**

`packages/extension-core/tests/url-match.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { isUrlAllowedForDomain, isTabUrlMatch } from '../src/lib/url-match.js';

describe('isUrlAllowedForDomain', () => {
  it('allows exact domain', () => {
    expect(isUrlAllowedForDomain('https://opentable.com/x', 'opentable.com')).toBe(true);
  });

  it('allows subdomain', () => {
    expect(isUrlAllowedForDomain('https://www.opentable.com/x', 'opentable.com')).toBe(true);
    expect(isUrlAllowedForDomain('https://api.opentable.com/x', 'opentable.com')).toBe(true);
  });

  it('rejects different domain', () => {
    expect(isUrlAllowedForDomain('https://yourbank.com/x', 'opentable.com')).toBe(false);
  });

  it('rejects suffix-attack domain', () => {
    // evilopentable.com should NOT match opentable.com
    expect(isUrlAllowedForDomain('https://evilopentable.com/x', 'opentable.com')).toBe(false);
  });

  it('rejects non-http(s) schemes', () => {
    expect(isUrlAllowedForDomain('javascript:alert(1)', 'opentable.com')).toBe(false);
    expect(isUrlAllowedForDomain('file:///etc/passwd', 'opentable.com')).toBe(false);
    expect(isUrlAllowedForDomain('data:text/html,<script>1</script>', 'opentable.com')).toBe(false);
  });

  it('rejects malformed URLs', () => {
    expect(isUrlAllowedForDomain('not a url', 'opentable.com')).toBe(false);
  });
});

describe('isTabUrlMatch', () => {
  it('prefix-matches against the tab URL', () => {
    expect(isTabUrlMatch('https://www.opentable.com/r/x?a=1', 'https://www.opentable.com/')).toBe(true);
  });

  it('does not match a different domain', () => {
    expect(isTabUrlMatch('https://evil.com/', 'https://www.opentable.com/')).toBe(false);
  });

  it('handles edge: exact equality', () => {
    expect(isTabUrlMatch('https://www.opentable.com/', 'https://www.opentable.com/')).toBe(true);
  });
});
```

- [ ] **Step 2: Write `packages/extension-core/package.json`**

```json
{
  "name": "@fetchproxy/extension-core",
  "version": "0.0.1",
  "private": true,
  "type": "module",
  "main": "./dist/index.js",
  "scripts": {
    "build": "tsc -b"
  },
  "dependencies": {
    "@fetchproxy/protocol": "*"
  },
  "devDependencies": {
    "@types/chrome": "^0.0.270"
  }
}
```

- [ ] **Step 3: Write `packages/extension-core/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src",
    "composite": true,
    "types": ["chrome"]
  },
  "include": ["src/**/*"],
  "references": [{ "path": "../protocol" }]
}
```

- [ ] **Step 4: Write `packages/extension-core/src/lib/url-match.ts`**

```typescript
/**
 * Domain allowlist + tab-URL prefix matching. Pure helpers, unit
 * tested. Defenses T3 (per-MCP scope) and the tab routing logic
 * for fetch requests.
 */

/**
 * Returns true iff `url` is on a domain the MCP is allowed to reach.
 * Allowed = exact hostname match OR a subdomain (`.foo.com` matches
 * `foo.com`). Rejects non-http(s) schemes outright (no javascript:,
 * data:, file:, etc.).
 */
export function isUrlAllowedForDomain(url: string, allowedDomain: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return false;
  }
  const host = parsed.hostname.toLowerCase();
  const allowed = allowedDomain.toLowerCase();
  return host === allowed || host.endsWith('.' + allowed);
}

/**
 * Returns true iff a tab's URL begins with the prefix the MCP server
 * supplied in `init.tabUrl`. The MCP picks a coarse prefix
 * ("https://www.opentable.com/") and the extension finds the first
 * matching open tab.
 */
export function isTabUrlMatch(tabUrl: string, prefix: string): boolean {
  return tabUrl.startsWith(prefix);
}
```

- [ ] **Step 5: Run tests**

```bash
npm test -- url-match
```

Expected: 9 tests pass.

- [ ] **Step 6: Commit**

```bash
git add packages/extension-core package.json package-lock.json
git commit -m "extension-core: url-match helpers (domain allowlist + tab match)

Two pure functions unit-tested in isolation:

- isUrlAllowedForDomain(url, allowedDomain) — exact hostname match OR
  subdomain (endsWith '.allowed'). Rejects non-http(s) schemes. The
  subdomain check uses '.' + allowed to defend against suffix-attack
  domains like evilopentable.com.

- isTabUrlMatch(tabUrl, prefix) — simple prefix match. The MCP server
  supplies a coarse prefix; extension picks the first open tab whose
  URL begins with it.

Both helpers are the security choke point for fetch routing —
exhaustive testing here pays for itself.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `extension-core` trust-store (chrome.storage CRUD)

**Files:**
- Create: `packages/extension-core/src/trust-store.ts`
- Create: `packages/extension-core/tests/trust-store.test.ts`

Persisted record of MCP servers the user has approved. Each entry: `{ port, server, version, domain, approval: 'always' | 'once' }`. The popup's trust-prompt UI writes here; the background SW reads here on every new connection.

- [ ] **Step 1: Write the failing test**

`packages/extension-core/tests/trust-store.test.ts`:

```typescript
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TrustStore, type TrustedMcp } from '../src/trust-store.js';

// Mock chrome.storage.local
function mockStorage() {
  const store = new Map<string, unknown>();
  return {
    get: vi.fn(async (keys?: string | string[]) => {
      if (!keys) return Object.fromEntries(store);
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const k of list) {
        if (store.has(k)) out[k] = store.get(k);
      }
      return out;
    }),
    set: vi.fn(async (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) store.set(k, v);
    }),
    remove: vi.fn(async (keys: string | string[]) => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) store.delete(k);
    }),
  };
}

describe('TrustStore', () => {
  let storage: ReturnType<typeof mockStorage>;
  let trust: TrustStore;

  beforeEach(() => {
    storage = mockStorage();
    trust = new TrustStore(storage as unknown as chrome.storage.StorageArea);
  });

  it('returns null for an unknown (port, server, domain) tuple', async () => {
    expect(await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }))
      .toBeNull();
  });

  it('persists an "always allow" decision and finds it back', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    const found = await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' });
    expect(found?.approval).toBe('always');
  });

  it('re-prompts (returns null) when the version major changes', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    const found = await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '1.0.0' });
    expect(found).toBeNull();
  });

  it('does not re-prompt on patch version bump', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    const found = await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.2' });
    expect(found?.approval).toBe('always');
  });

  it('re-prompts when the domain changes', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    const found = await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'yourbank.com', version: '0.9.1' });
    expect(found).toBeNull();
  });

  it('revokes an approval', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    await trust.revoke({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com' });
    expect(await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }))
      .toBeNull();
  });

  it('lists all trusted MCPs', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    await trust.approve({ port: 37148, server: 'resy-mcp', domain: 'resy.com', version: '0.1.0' }, 'always');
    const list = await trust.list();
    expect(list).toHaveLength(2);
    expect(list.map((m: TrustedMcp) => m.server).sort()).toEqual(['opentable-mcp', 'resy-mcp']);
  });
});
```

- [ ] **Step 2: Write `packages/extension-core/src/trust-store.ts`**

```typescript
/**
 * Persistent record of MCP servers the user has trusted. Keyed on
 * (port, server, domain). Major-version changes invalidate the
 * approval (T8 in the threat model — surface re-prompts on
 * meaningful identity drift); patch/minor changes carry the approval
 * forward to avoid prompt fatigue.
 *
 * Storage area is chrome.storage.local for production; tests inject
 * an in-memory mock.
 */

export type Approval = 'always' | 'once';

export interface McpIdentity {
  port: number;
  server: string;
  version: string;
  domain: string;
}

export interface TrustedMcp extends McpIdentity {
  approval: Approval;
  approved_at: number; // unix ms
}

const KEY_PREFIX = 'trustedMcp:';

function key(id: { port: number; server: string; domain: string }): string {
  return `${KEY_PREFIX}${id.port}|${id.server}|${id.domain}`;
}

/** Extract major version. `"0.9.1"` → `0`; `"1.2.3"` → `1`. Returns
 *  empty string if not parseable so we always re-prompt on garbage. */
function major(version: string): string {
  const m = version.match(/^(\d+)\./);
  return m?.[1] ?? '';
}

export class TrustStore {
  constructor(private readonly storage: chrome.storage.StorageArea) {}

  async lookup(id: McpIdentity): Promise<TrustedMcp | null> {
    const k = key(id);
    const got = await this.storage.get(k);
    const entry = got[k] as TrustedMcp | undefined;
    if (!entry) return null;
    // Major-version change invalidates the approval.
    if (major(entry.version) !== major(id.version)) return null;
    return entry;
  }

  async approve(id: McpIdentity, approval: Approval): Promise<void> {
    const k = key(id);
    const entry: TrustedMcp = {
      ...id,
      approval,
      approved_at: Date.now(),
    };
    await this.storage.set({ [k]: entry });
  }

  async revoke(id: { port: number; server: string; domain: string }): Promise<void> {
    await this.storage.remove(key(id));
  }

  async list(): Promise<TrustedMcp[]> {
    const all = await this.storage.get();
    const out: TrustedMcp[] = [];
    for (const [k, v] of Object.entries(all)) {
      if (k.startsWith(KEY_PREFIX)) out.push(v as TrustedMcp);
    }
    return out;
  }
}
```

- [ ] **Step 3: Run tests**

```bash
npm test -- trust-store
```

Expected: 7 tests pass.

- [ ] **Step 4: Commit**

```bash
git add packages/extension-core
git commit -m "extension-core: trust-store (chrome.storage-backed MCP allowlist)

Persistent record of which (port, server, domain) tuples the user
has approved. Lookups are tolerant of patch/minor version drift but
re-prompt on major-version bumps and any domain change (T8 in the
threat model).

API:
  lookup(id) → TrustedMcp | null
  approve(id, 'always' | 'once') → void
  revoke({ port, server, domain }) → void
  list() → TrustedMcp[]

Keyed on \`trustedMcp:<port>|<server>|<domain>\`. chrome.storage.local
in production; tests inject an in-memory mock.

7 unit tests cover: unknown lookup, always-allow persistence,
major/minor/patch version semantics, domain-change re-prompt,
revoke, list.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `extension-core` background.ts (service worker)

**Files:**
- Create: `packages/extension-core/src/background.ts`

Service worker that connects to each configured MCP server, handles the trust prompt flow, and routes fetch requests to tabs. This file is hard to unit-test (depends on browser APIs); we manually smoke-test in Task 9.

- [ ] **Step 1: Write the file**

```typescript
/**
 * Background service worker entry. Owns:
 *   - WS connections to each trusted MCP server (one per port)
 *   - Trust-prompt flow for new connections
 *   - Per-MCP domain allowlist enforcement on every fetch
 *   - Tab routing: pick a tab matching `init.tabUrl`, send fetch RPC
 *
 * Configuration is read from chrome.storage (a list of server ports
 * the user has added in the popup). Each entry is { port, name? }
 * — the actual server identity comes from its `hello` frame.
 */
import {
  validateFrame,
  type Frame,
  type HelloServer,
  type FetchRequest,
} from '@fetchproxy/protocol';
import { TrustStore, type McpIdentity } from './trust-store.js';
import { isUrlAllowedForDomain, isTabUrlMatch } from './lib/url-match.js';

const EXTENSION_VERSION = chrome.runtime.getManifest().version;
const PING_INTERVAL_MS = 20_000;
const STORAGE_PORTS_KEY = 'configuredPorts';

interface ConfiguredPort {
  port: number;
  /** Display name (user-supplied or last-seen server name). */
  label?: string;
}

interface Connection {
  port: number;
  ws: WebSocket;
  serverHello?: HelloServer;
  pingTimer?: ReturnType<typeof setInterval>;
}

const trust = new TrustStore(chrome.storage.local);
const connections = new Map<number, Connection>();

/** Open WebSocket connections to every configured port. Called on
 *  service worker startup + when the user adds/removes ports. */
async function reconcileConnections(): Promise<void> {
  const got = await chrome.storage.local.get(STORAGE_PORTS_KEY);
  const desired: ConfiguredPort[] = (got[STORAGE_PORTS_KEY] as ConfiguredPort[] | undefined) ?? [];

  // Close any connection to a port no longer configured.
  for (const [port, conn] of connections) {
    if (!desired.find((d) => d.port === port)) {
      conn.ws.close();
      if (conn.pingTimer) clearInterval(conn.pingTimer);
      connections.delete(port);
    }
  }
  // Open any newly-configured port.
  for (const d of desired) {
    if (!connections.has(d.port)) connect(d.port);
  }
}

function connect(port: number): void {
  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  const conn: Connection = { port, ws };
  connections.set(port, conn);

  ws.addEventListener('open', () => {
    ws.send(JSON.stringify({
      type: 'hello',
      role: 'extension',
      version: EXTENSION_VERSION,
      platform: 'chrome',
      extension_id: 'fetchproxy',
    }));
    conn.pingTimer = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, PING_INTERVAL_MS);
  });

  ws.addEventListener('message', async (ev) => {
    let frame: Frame;
    try {
      frame = validateFrame(JSON.parse(ev.data));
    } catch {
      ws.close(1002);
      return;
    }
    await handleFrame(conn, frame);
  });

  ws.addEventListener('close', () => {
    if (conn.pingTimer) clearInterval(conn.pingTimer);
    connections.delete(port);
    // Reconnect after 2s. Bound by service worker lifetime.
    setTimeout(() => {
      chrome.storage.local.get(STORAGE_PORTS_KEY).then((got) => {
        const stillConfigured = (got[STORAGE_PORTS_KEY] as ConfiguredPort[] | undefined)
          ?.find((d) => d.port === port);
        if (stillConfigured) connect(port);
      });
    }, 2000);
  });

  ws.addEventListener('error', () => {
    // The close handler will run too; nothing to do here.
  });
}

async function handleFrame(conn: Connection, frame: Frame): Promise<void> {
  switch (frame.type) {
    case 'hello':
      if (frame.role !== 'server') return;
      conn.serverHello = frame;
      // Check trust before sending ready.
      await maybePromptTrust(conn, frame);
      return;
    case 'ping':
      conn.ws.send(JSON.stringify({ type: 'pong' }));
      return;
    case 'pong':
      return;
    case 'request':
      await handleFetchRequest(conn, frame);
      return;
    default:
      return;
  }
}

async function maybePromptTrust(conn: Connection, hello: HelloServer): Promise<void> {
  const id: McpIdentity = {
    port: conn.port,
    server: hello.server,
    version: hello.version,
    domain: hello.domain,
  };
  const known = await trust.lookup(id);
  if (known?.approval === 'always') {
    // Already trusted. Verify a matching tab exists, then send ready.
    if (await hasMatchingTab(hello.domain)) {
      conn.ws.send(JSON.stringify({ type: 'ready' }));
    }
    return;
  }
  // Open the popup as a window with the trust prompt. The popup will
  // call trust.approve() or send a "block" message, then we re-evaluate.
  // For implementation simplicity we just queue a pending-trust state;
  // the popup polls trust-store on open.
  await chrome.storage.session.set({
    [`pendingTrust:${conn.port}`]: {
      ...id,
      requested_at: Date.now(),
    },
  });
  // Open popup window for the prompt.
  chrome.action.openPopup?.();
}

async function hasMatchingTab(domain: string): Promise<boolean> {
  const tabs = await chrome.tabs.query({});
  return tabs.some((t) => {
    if (!t.url) return false;
    try {
      const u = new URL(t.url);
      return u.hostname === domain || u.hostname.endsWith('.' + domain);
    } catch {
      return false;
    }
  });
}

async function handleFetchRequest(conn: Connection, req: FetchRequest): Promise<void> {
  const hello = conn.serverHello;
  if (!hello) {
    sendErr(conn, req.id, 'no server hello yet');
    return;
  }

  // Domain allowlist enforcement.
  if (!isUrlAllowedForDomain(req.init.url, hello.domain)) {
    sendErr(conn, req.id, `url not in allowed domain (${hello.domain}): ${req.init.url}`);
    return;
  }

  // Find a tab matching tabUrl.
  const tabs = await chrome.tabs.query({});
  const tab = tabs.find((t) => t.url && isTabUrlMatch(t.url, req.init.tabUrl));
  if (!tab || tab.id === undefined) {
    sendErr(conn, req.id, `no tab matching ${req.init.tabUrl}`);
    return;
  }

  try {
    const response = await chrome.tabs.sendMessage(tab.id, {
      kind: 'fetchproxy-fetch',
      init: req.init,
    });
    if (response?.ok) {
      conn.ws.send(JSON.stringify({
        type: 'response',
        id: req.id,
        ok: true,
        status: response.status,
        url: response.url,
        body: response.body,
      }));
    } else {
      sendErr(conn, req.id, response?.error ?? 'fetch failed');
    }
  } catch (e) {
    // Content script not injected — self-heal by injecting and retrying.
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js'],
      });
      const retry = await chrome.tabs.sendMessage(tab.id, {
        kind: 'fetchproxy-fetch',
        init: req.init,
      });
      if (retry?.ok) {
        conn.ws.send(JSON.stringify({
          type: 'response',
          id: req.id,
          ok: true,
          status: retry.status,
          url: retry.url,
          body: retry.body,
        }));
      } else {
        sendErr(conn, req.id, retry?.error ?? 'fetch failed after content-script re-inject');
      }
    } catch (e2) {
      sendErr(conn, req.id, `content script unreachable: ${(e2 as Error).message}`);
    }
  }
}

function sendErr(conn: Connection, id: number, error: string): void {
  conn.ws.send(JSON.stringify({ type: 'response', id, ok: false, error }));
}

// Service worker entry.
chrome.runtime.onInstalled.addListener(() => reconcileConnections());
chrome.runtime.onStartup.addListener(() => reconcileConnections());
chrome.storage.onChanged.addListener((changes) => {
  if (changes[STORAGE_PORTS_KEY]) reconcileConnections();
  // When the user approves a pending trust, re-evaluate the connection.
  for (const k of Object.keys(changes)) {
    if (k.startsWith('trustedMcp:')) {
      for (const [, conn] of connections) {
        if (conn.serverHello) {
          maybePromptTrust(conn, conn.serverHello).catch(() => {});
        }
      }
    }
  }
});

reconcileConnections();
```

- [ ] **Step 2: Commit**

```bash
git add packages/extension-core/src/background.ts
git commit -m "extension-core: background service worker

Owns: WS connections to configured MCP ports, trust-prompt flow,
per-MCP domain allowlist enforcement, tab routing for fetch RPCs.

Trust flow:
1. Connection opens; server sends its hello.
2. Background checks trust-store for (port, server, domain).
3. If 'always' approval found AND a tab matching domain is open,
   send 'ready'. Otherwise stash a pendingTrust entry in
   chrome.storage.session and open the popup for the prompt.
4. When the popup calls trust.approve('always'), the
   storage.onChanged listener re-evaluates the pending connection.

Fetch flow:
1. Receive request frame, validate via @fetchproxy/protocol.
2. Reject if init.url not in serverHello.domain.
3. Find a tab matching init.tabUrl (first hit wins).
4. chrome.tabs.sendMessage to the content script; on failure
   (no content script), inject via chrome.scripting and retry.
5. Return response frame.

Self-heal pattern carries over from opentable-mcp's existing
extension. Reconnect with 2s backoff after WS close.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `extension-core` content.ts (in-page fetch executor)

**Files:**
- Create: `packages/extension-core/src/content.ts`

Content script that listens for `fetchproxy-fetch` messages from the service worker and runs the actual `fetch()` in the page's MAIN world (via injecting a `<script>` tag with the fetch call). The isolated-world content script cannot access page CSRF/auth state directly, but the MAIN-world fetch inherits all cookies and credentials.

For the v1 Chrome MVP we use a simpler pattern: the content script just runs `fetch()` from the isolated world. Cookies + credentials work fine; we don't need MAIN-world for the basic flow. (MAIN-world capture-logger is deferred to Phase 3 per the spec.)

- [ ] **Step 1: Write the file**

```typescript
/**
 * Content script (isolated world). Listens for fetch RPC messages
 * from the background service worker, runs window.fetch in the
 * page context with credentials: 'include', returns the response.
 *
 * The isolated-world fetch inherits cookies + the user's TLS
 * fingerprint — which is exactly what Akamai/Cloudflare want to see.
 * The page's own auth state (CSRF tokens that live on window.*) is
 * NOT directly accessible; for the v1 booking flow we don't need
 * them in this codebase — the MCP server can include them via
 * init.headers if needed.
 */

const MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024; // 1 MB
const MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024; // 5 MB

interface FetchInit {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  tabUrl: string;
}

interface FetchResponse {
  ok: true;
  status: number;
  url: string;
  body: string;
}

interface FetchError {
  ok: false;
  error: string;
}

chrome.runtime.onMessage.addListener((msg: { kind?: string; init?: FetchInit }, _sender, sendResponse) => {
  if (msg.kind !== 'fetchproxy-fetch' || !msg.init) return false;

  void runFetch(msg.init)
    .then(sendResponse)
    .catch((e: unknown) => sendResponse({ ok: false, error: (e as Error).message } satisfies FetchError));
  return true; // tells Chrome we'll respond asynchronously
});

async function runFetch(init: FetchInit): Promise<FetchResponse | FetchError> {
  if (init.body && init.body.length > MAX_REQUEST_BODY_BYTES) {
    return { ok: false, error: `request body too large: ${init.body.length} bytes` };
  }
  let response: Response;
  try {
    response = await window.fetch(init.url, {
      method: init.method,
      headers: init.headers,
      body: init.body,
      credentials: 'include',
    });
  } catch (e) {
    return { ok: false, error: `fetch threw: ${(e as Error).message}` };
  }
  let body: string;
  try {
    body = await response.text();
  } catch (e) {
    return { ok: false, error: `response.text() threw: ${(e as Error).message}` };
  }
  if (body.length > MAX_RESPONSE_BODY_BYTES) {
    return { ok: false, error: `response body too large: ${body.length} bytes` };
  }
  return {
    ok: true,
    status: response.status,
    url: response.url,
    body,
  };
}
```

- [ ] **Step 2: Commit**

```bash
git add packages/extension-core/src/content.ts
git commit -m "extension-core: content.ts (in-page fetch executor)

Isolated-world content script. Listens for 'fetchproxy-fetch'
messages from the background SW, runs window.fetch with
credentials: 'include' in the page context, returns the response.

Body size limits at this layer too (1 MB request, 5 MB response).
A second line of defense alongside the server-side cap.

We do NOT use a MAIN-world script in v1 — the isolated-world fetch
inherits cookies + TLS fingerprint, which is all we need for the
Akamai-passing booking flow. MAIN-world capture-logger (for
endpoint discovery) is deferred to Phase 3 per the spec.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: `extension-core` popup (trust prompt + status)

**Files:**
- Create: `packages/extension-core/src/popup/popup.html`
- Create: `packages/extension-core/src/popup/popup.ts`

Popup UI. Three modes, dispatched on what `chrome.storage.session` has:
1. **Pending trust prompt** — show the "Allow MCP <name> on <domain>?" approval.
2. **Status (default)** — list each configured MCP, show connection state, allow add/remove.
3. **Empty state** — no MCPs configured; show "Add your first MCP server (port number)".

This file is the largest manual-test surface. The trust-store and url-match unit tests already cover the logic; the popup is a thin shell around them.

- [ ] **Step 1: Write `popup.html`**

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>fetchproxy</title>
    <style>
      body {
        font-family: -apple-system, BlinkMacSystemFont, sans-serif;
        min-width: 380px;
        margin: 0;
        padding: 12px;
        font-size: 14px;
      }
      h1 { font-size: 16px; margin: 0 0 12px; }
      .prompt {
        background: #fff7e6;
        border: 1px solid #f5c45e;
        border-radius: 6px;
        padding: 12px;
        margin-bottom: 12px;
      }
      .prompt .domain {
        font-size: 18px;
        font-weight: 600;
        color: #b45309;
        margin: 8px 0;
      }
      .prompt .buttons { display: flex; gap: 8px; margin-top: 12px; }
      .prompt button { flex: 1; padding: 8px; border-radius: 4px; border: 1px solid #ccc; cursor: pointer; }
      .prompt button.always { background: #2563eb; color: white; border-color: #2563eb; }
      .prompt button.block { background: #fef2f2; color: #b91c1c; border-color: #fca5a5; }
      .mcp-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid #eee; }
      .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
      .dot.green { background: #22c55e; }
      .dot.red { background: #ef4444; }
      .dot.yellow { background: #eab308; }
      .add-row { margin-top: 12px; display: flex; gap: 6px; }
      .add-row input { flex: 1; padding: 6px; }
      .add-row button { padding: 6px 12px; }
      .empty { color: #6b7280; text-align: center; padding: 16px 0; }
    </style>
  </head>
  <body>
    <h1>fetchproxy</h1>
    <div id="root">Loading…</div>
    <script type="module" src="popup.js"></script>
  </body>
</html>
```

- [ ] **Step 2: Write `popup.ts`**

```typescript
import { TrustStore, type TrustedMcp, type McpIdentity } from '../trust-store.js';

interface ConfiguredPort {
  port: number;
  label?: string;
}

interface PendingTrust extends McpIdentity {
  requested_at: number;
}

const trust = new TrustStore(chrome.storage.local);
const root = document.getElementById('root')!;

const HIGH_RISK_DOMAINS = new Set(['bank', 'gov', 'mil']); // TLD-based; expanded in v2

function isHighRisk(domain: string): boolean {
  const tld = domain.split('.').pop();
  return tld ? HIGH_RISK_DOMAINS.has(tld) : false;
}

async function render(): Promise<void> {
  // 1) Pending trust prompts take priority.
  const session = await chrome.storage.session.get();
  const pending: PendingTrust[] = [];
  for (const [k, v] of Object.entries(session)) {
    if (k.startsWith('pendingTrust:')) pending.push(v as PendingTrust);
  }
  if (pending.length > 0) {
    renderPrompt(pending[0]!);
    return;
  }

  // 2) Status view.
  const local = await chrome.storage.local.get('configuredPorts');
  const configured: ConfiguredPort[] = (local.configuredPorts as ConfiguredPort[] | undefined) ?? [];
  const trusted = await trust.list();
  renderStatus(configured, trusted);
}

function renderPrompt(p: PendingTrust): void {
  const risky = isHighRisk(p.domain);
  root.innerHTML = `
    <div class="prompt">
      <div>A new MCP server wants to relay HTTP requests through your browser:</div>
      <div class="domain">${escape(p.domain)}</div>
      <div style="font-size: 12px; color: #6b7280;">
        Server: ${escape(p.server)} v${escape(p.version)}<br>
        Port: ${p.port}
      </div>
      ${risky ? `<div style="margin-top: 8px; color: #b91c1c;">⚠️ High-risk domain (${escape(p.domain.split('.').pop() ?? '')}).</div>` : ''}
      <div class="buttons">
        <button class="block" id="block">Block</button>
        <button id="once">Allow once</button>
        <button class="always" id="always">Always allow</button>
      </div>
    </div>
  `;
  document.getElementById('block')!.addEventListener('click', async () => {
    await chrome.storage.session.remove(`pendingTrust:${p.port}`);
    render();
  });
  document.getElementById('once')!.addEventListener('click', async () => {
    await trust.approve({ port: p.port, server: p.server, domain: p.domain, version: p.version }, 'once');
    await chrome.storage.session.remove(`pendingTrust:${p.port}`);
    render();
  });
  document.getElementById('always')!.addEventListener('click', async () => {
    await trust.approve({ port: p.port, server: p.server, domain: p.domain, version: p.version }, 'always');
    await chrome.storage.session.remove(`pendingTrust:${p.port}`);
    render();
  });
}

function renderStatus(configured: ConfiguredPort[], trusted: TrustedMcp[]): void {
  const rows = configured.map((c) => {
    const t = trusted.find((m) => m.port === c.port);
    const dot = t ? '<span class="dot green"></span>' : '<span class="dot yellow"></span>';
    const label = t ? `${escape(t.server)} (${escape(t.domain)})` : `Port ${c.port} — waiting for trust`;
    return `<div class="mcp-row">${dot}${label}<button data-port="${c.port}" class="remove">Remove</button></div>`;
  });
  root.innerHTML = `
    ${rows.length === 0 ? '<div class="empty">No MCP servers configured. Add one below.</div>' : rows.join('')}
    <div class="add-row">
      <input id="port-input" type="number" placeholder="Port (e.g. 37149)">
      <button id="add">Add</button>
    </div>
  `;
  document.querySelectorAll<HTMLButtonElement>('button.remove').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const port = Number(btn.dataset.port);
      const local = await chrome.storage.local.get('configuredPorts');
      const list = ((local.configuredPorts as ConfiguredPort[] | undefined) ?? []).filter((c) => c.port !== port);
      await chrome.storage.local.set({ configuredPorts: list });
      const found = trusted.find((m) => m.port === port);
      if (found) await trust.revoke({ port: found.port, server: found.server, domain: found.domain });
      render();
    });
  });
  document.getElementById('add')!.addEventListener('click', async () => {
    const input = document.getElementById('port-input') as HTMLInputElement;
    const port = Number(input.value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return;
    const local = await chrome.storage.local.get('configuredPorts');
    const list = ((local.configuredPorts as ConfiguredPort[] | undefined) ?? []).filter((c) => c.port !== port);
    list.push({ port });
    await chrome.storage.local.set({ configuredPorts: list });
    render();
  });
}

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

render();
chrome.storage.onChanged.addListener(() => render());
```

- [ ] **Step 3: Commit**

```bash
git add packages/extension-core/src/popup
git commit -m "extension-core: popup (trust prompt + status + add/remove)

Three-mode UI dispatched on chrome.storage.session state:

1. Pending trust prompt — if a connection is waiting for approval,
   shows 'Allow MCP <name> on <domain>?' with three buttons: Block,
   Allow once, Always allow. Domain rendered in large amber text.
   High-risk TLD (bank, gov, mil) gets an extra warning. 'Always'
   persists via TrustStore.approve('always').

2. Status — lists each configured port with a status dot (green =
   trusted+connected, yellow = waiting for trust). Each row has a
   Remove button that strips both the configured port and any
   trust entry.

3. Add — port-number input + Add button for new MCP entries.

HTML escapes server/domain/version everywhere they're rendered.
storage.onChanged triggers re-render automatically.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: `extension-chrome` MV3 manifest + esbuild bundle

**Files:**
- Create: `packages/extension-chrome/package.json`
- Create: `packages/extension-chrome/manifest.json`
- Create: `packages/extension-chrome/build.ts`
- Create: `packages/extension-chrome/icons/16.png` (placeholder; can be a solid color)
- Create: `packages/extension-chrome/icons/48.png`
- Create: `packages/extension-chrome/icons/128.png`

Builds a loadable Chrome extension from the extension-core sources. Output goes to `packages/extension-chrome/dist/`. User loads that dir at `chrome://extensions` → "Load unpacked".

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "@fetchproxy/extension-chrome",
  "version": "0.0.1",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "tsx build.ts"
  },
  "dependencies": {
    "@fetchproxy/extension-core": "*",
    "@fetchproxy/protocol": "*"
  },
  "devDependencies": {
    "esbuild": "^0.28.0",
    "tsx": "^4.19.0"
  }
}
```

- [ ] **Step 2: Write `manifest.json`**

```json
{
  "manifest_version": 3,
  "name": "fetchproxy",
  "version": "0.0.1",
  "description": "Relay authenticated fetch() from MCP servers through your signed-in browser tab.",
  "icons": {
    "16": "icons/16.png",
    "48": "icons/48.png",
    "128": "icons/128.png"
  },
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/16.png",
      "48": "icons/48.png",
      "128": "icons/128.png"
    }
  },
  "background": {
    "service_worker": "background.js",
    "type": "module"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_idle",
      "world": "ISOLATED"
    }
  ],
  "permissions": [
    "storage",
    "tabs",
    "scripting"
  ],
  "host_permissions": [
    "<all_urls>"
  ]
}
```

- [ ] **Step 3: Write `build.ts`**

```typescript
import { build } from 'esbuild';
import { mkdir, copyFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const OUT = 'dist';

async function main(): Promise<void> {
  await mkdir(OUT, { recursive: true });
  await mkdir(join(OUT, 'icons'), { recursive: true });

  // Bundle each entry point.
  await build({
    entryPoints: {
      background: '../extension-core/src/background.ts',
      content: '../extension-core/src/content.ts',
      popup: '../extension-core/src/popup/popup.ts',
    },
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: 'chrome120',
    outdir: OUT,
    sourcemap: 'inline',
  });

  // Copy static files.
  await copyFile('manifest.json', join(OUT, 'manifest.json'));
  await copyFile('../extension-core/src/popup/popup.html', join(OUT, 'popup.html'));
  // Icons (placeholder solid-color PNGs; replace with real artwork later)
  for (const f of await readdir('icons')) {
    await copyFile(join('icons', f), join(OUT, 'icons', f));
  }
  console.log('extension-chrome built →', OUT);
}

void main();
```

- [ ] **Step 4: Generate placeholder icons**

A 16/48/128 solid orange PNG triplet, generated however you like (ImageMagick, an online tool, or just commit three small placeholder files). Color: `#f59e0b` matches the "amber prompt" theme.

```bash
# Example with ImageMagick:
for s in 16 48 128; do
  convert -size ${s}x${s} xc:'#f59e0b' packages/extension-chrome/icons/${s}.png
done
```

(If ImageMagick isn't installed, any 16/48/128 PNG works. The Chrome Store will eventually require real artwork.)

- [ ] **Step 5: Build + verify**

```bash
npm run build --workspace @fetchproxy/extension-chrome
ls packages/extension-chrome/dist/
```

Expected: `dist/` contains `background.js`, `content.js`, `popup.js`, `popup.html`, `manifest.json`, `icons/`.

- [ ] **Step 6: Commit**

```bash
git add packages/extension-chrome
git commit -m "extension-chrome: MV3 manifest + esbuild bundle

Builds the Chrome extension dist/ from the extension-core sources.
Three esbuild entry points (background, content, popup), all ESM.
Static files (manifest.json, popup.html, icons/) copied alongside.

To load:
  chrome://extensions → Load unpacked → packages/extension-chrome/dist/

Icons are placeholder solid amber PNGs; replace with real artwork
before any Chrome Store submission.

Permissions:
  - storage (chrome.storage.local + .session)
  - tabs (chrome.tabs.query, .sendMessage)
  - scripting (self-heal content script via chrome.scripting.executeScript)

host_permissions: <all_urls> — needed for content_scripts to inject
on any domain an MCP wants to fetch from. The per-MCP domain
allowlist enforced in background.ts is the actual scope guard.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: End-to-end smoke test (controller-driven)

**Files:** none (manual verification)

Hand-run by the controller (you) with the bridged Chrome tab. Loads the new extension and confirms it serves opentable-mcp's existing booking flow without regression.

- [ ] **Step 1: Build everything**

```bash
cd /Users/chris/git/fetchproxy
npm run build
```

- [ ] **Step 2: Load the extension unpacked**

Chrome → `chrome://extensions` → toggle Developer mode → "Load unpacked" → select `packages/extension-chrome/dist/`. Confirm the extension icon appears in the toolbar.

- [ ] **Step 3: Configure the opentable-mcp port**

Click the extension icon → enter `37149` → Add. Status row appears with yellow dot ("waiting for trust").

- [ ] **Step 4: Stand up a fetchproxy-server instance for opentable-mcp**

This step requires opentable-mcp to be already migrated (Task 11). For Task 9's purpose, run a smoke-test harness — a tiny Node script that uses `@fetchproxy/server` directly:

```typescript
// /tmp/smoke.ts
import { FetchproxyServer } from '/Users/chris/git/fetchproxy/packages/server/dist/index.js';
const s = new FetchproxyServer({
  port: 37149,
  server: 'opentable-mcp',
  version: '0.9.1',
  domain: 'opentable.com',
});
await s.start();
console.log('listening on 37149; click the extension icon to approve');
// Wait 30s then fetch
await new Promise((r) => setTimeout(r, 30_000));
const result = await s.fetch({
  url: 'https://www.opentable.com/user/dining-dashboard',
  method: 'GET',
  tabUrl: 'https://www.opentable.com/',
});
console.log('status:', result.status, 'body length:', result.body.length);
await s.close();
```

Run: `npx tsx /tmp/smoke.ts`

- [ ] **Step 5: Approve trust prompt**

Within 5s of the server starting, click the extension icon. Trust prompt should appear:
> A new MCP server wants to relay HTTP requests through your browser:
> **opentable.com**
> Server: opentable-mcp v0.9.1
> Port: 37149
> [Block] [Allow once] [Always allow]

Click "Always allow".

- [ ] **Step 6: Verify fetch round-trip**

Wait for the smoke script's 30s timer + the fetch. The console should print:
```
status: 200 body length: <some big number>
```

If `status: 200` and a non-trivial body, the round-trip works.

- [ ] **Step 7: Verify domain enforcement**

Modify the smoke script's fetch URL to `https://yourbank.com/` (or any non-opentable.com domain). Re-run. Expected: the fetch rejects with `url not in allowed domain (opentable.com): https://yourbank.com/`.

- [ ] **Step 8: Verify webpage-origin rejection**

From DevTools on an opentable.com tab, in the console:
```javascript
new WebSocket('ws://127.0.0.1:37149');
```
Wait. The connection should close immediately (Origin header rejection). Check with `setTimeout(() => console.log(ws.readyState), 500)` — should be 3 (CLOSED).

- [ ] **Step 9: Notes**

Capture any issues found. If anything fails, the failure goes into a follow-up task or is fixed inline before Task 11.

---

### Task 10: Migrate `opentable-mcp` to depend on `@fetchproxy/server`

**Files (in `/Users/chris/git/opentable-mcp/`):**
- Modify: `package.json` (add `@fetchproxy/server` dep, remove `ws` dep)
- Modify: `src/ws-server.ts` → delete (move functionality to depend on the lib)
- Modify: `src/index.ts` (use `FetchproxyServer` instead of `OpenTableWsServer`)
- Modify: `src/transport.ts` (no longer needs its own implementation; `@fetchproxy/server` exports `FetchproxyServer` which implements the same `OpenTableTransport` interface — adapt)
- Modify: `tests/ws-server.test.ts` → delete (tested in `@fetchproxy/server`)
- Modify: `CLAUDE.md` (note the new dependency)
- Delete: `extension/` directory (old extension is now redundant)

This is the cross-repo cutover. opentable-mcp's `OpenTableWsServer` becomes a thin wrapper or is entirely replaced by `FetchproxyServer`.

- [ ] **Step 1: Add fetchproxy as a local file dependency for development**

In `/Users/chris/git/opentable-mcp/package.json`:

```json
{
  "dependencies": {
    "@fetchproxy/server": "file:../fetchproxy/packages/server",
    "@modelcontextprotocol/sdk": "^1.29.0",
    "dotenv": "^17.4.0",
    "zod": "^4.3.6"
  }
}
```

Remove the `ws` direct dependency (it's transitive via `@fetchproxy/server` now).

Run:

```bash
cd /Users/chris/git/opentable-mcp
npm install
```

- [ ] **Step 2: Adapt `src/index.ts`**

Find where `OpenTableWsServer` is instantiated. Replace with:

```typescript
import { FetchproxyServer } from '@fetchproxy/server';

const transport = new FetchproxyServer({
  port: Number(process.env.OT_WS_PORT ?? 37149),
  server: 'opentable-mcp',
  version: VERSION, // from package.json or const
  domain: 'opentable.com',
});
await transport.start();
```

- [ ] **Step 3: Adapt `src/transport.ts`**

`FetchproxyServer` implements the same `fetch()` signature; the existing `OpenTableTransport` interface is a superset (includes `start()`, `close()`). Update the type aliases so `FetchproxyServer` satisfies `OpenTableTransport` directly.

If shape diverges, write a thin adapter:

```typescript
import type { FetchInit as ProtocolFetchInit, FetchResult } from '@fetchproxy/server';
import type { OpenTableTransport } from './transport.js';

export function adaptFetchproxy(s: FetchproxyServer): OpenTableTransport {
  return {
    start: () => s.start(),
    close: () => s.close(),
    fetch: (init) => s.fetch(init),
  };
}
```

- [ ] **Step 4: Delete `src/ws-server.ts` and `tests/ws-server.test.ts`**

```bash
git rm src/ws-server.ts tests/ws-server.test.ts
```

- [ ] **Step 5: Delete `extension/`**

```bash
git rm -r extension/
```

- [ ] **Step 6: Update `CLAUDE.md`**

Replace the "extension/" section with a note about depending on `@fetchproxy/server` + linking to the fetchproxy repo. Update the architecture diagram.

- [ ] **Step 7: Run opentable-mcp's full test suite**

```bash
cd /Users/chris/git/opentable-mcp
npm test
```

Expected: all tests pass (modulo the deleted ws-server.test.ts).

- [ ] **Step 8: Build opentable-mcp**

```bash
npm run build
```

Expected: bundle builds clean.

- [ ] **Step 9: Live smoke**

```bash
lsof -ti :37149 | xargs -r kill 2>/dev/null
sleep 2
npx tsx scripts/probe-find-slots.ts
```

Expected: a known-good probe (the simplest one) works against the new fetchproxy extension. If it works, the migration is good.

- [ ] **Step 10: Commit on a feature branch**

```bash
git checkout -b feat/migrate-to-fetchproxy
git add -A
git commit -m "feat: migrate to @fetchproxy/server

Replaces the in-tree OpenTableWsServer + ./extension/ with a
dependency on @fetchproxy/server. The user installs fetchproxy
(Chrome Store / Safari .dmg) once instead of loading our embedded
extension; all booking flows go through the same WS bridge.

Removed:
- src/ws-server.ts        (now @fetchproxy/server's FetchproxyServer)
- tests/ws-server.test.ts (covered upstream)
- extension/              (replaced by the fetchproxy extension)

Added:
- @fetchproxy/server dependency
- Thin adapter in src/transport.ts (if needed) to satisfy the existing
  OpenTableTransport interface

All other behavior is unchanged. Live verified: probe-find-slots
returns the expected slot data against opentable.com.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 11: Do NOT push or open the PR yet**

Hold this commit local until the fetchproxy repo is published (Task 11). The file:../ dep won't work for downstream consumers; we need a published `@fetchproxy/server` first.

---

### Task 11: Publish + open the fetchproxy PR

**Files:** none

Set up the npm publish flow and open the initial fetchproxy PR.

- [ ] **Step 1: Set up npm publish for @fetchproxy/protocol and @fetchproxy/server**

These are public packages. Make sure each `package.json` has:

```json
{
  "publishConfig": {
    "access": "public"
  }
}
```

- [ ] **Step 2: Initial publish (dry-run)**

```bash
cd /Users/chris/git/fetchproxy
npm publish --workspace @fetchproxy/protocol --dry-run
npm publish --workspace @fetchproxy/server --dry-run
```

Verify the file list looks right.

- [ ] **Step 3: Real publish**

```bash
npm publish --workspace @fetchproxy/protocol
npm publish --workspace @fetchproxy/server
```

- [ ] **Step 4: Push the fetchproxy repo to GitHub**

Create the GitHub repo (private or public; user's call). Push main:

```bash
cd /Users/chris/git/fetchproxy
gh repo create chrischall/fetchproxy --private --source=. --remote=origin --push
```

- [ ] **Step 5: Open initial fetchproxy PR (or merge straight to main)**

Since this is the initial commit set on `main`, you can either:
- Push directly to main (user's pattern: solo work that's not under PR review)
- Open a "v0.0.1 — initial Chrome MVP" PR for visible history

Either way works. The auto-merge workflow can be added in a follow-up.

- [ ] **Step 6: Bump opentable-mcp's dep to the published version**

Back in `/Users/chris/git/opentable-mcp/` on the `feat/migrate-to-fetchproxy` branch:

```bash
npm install @fetchproxy/server@^0.0.1
```

This rewrites `package.json` from `file:../fetchproxy/...` to the published version.

- [ ] **Step 7: Re-run opentable-mcp tests + build**

```bash
npm test && npm run build
```

- [ ] **Step 8: Open the opentable-mcp PR**

```bash
git push -u origin feat/migrate-to-fetchproxy
gh pr create --label enhancement --title "feat: migrate to @fetchproxy/server" --body "$(cat <<'BODY'
## Summary

Migrates from the embedded WS bridge + \`./extension/\` to depending on \`@fetchproxy/server\` (published from the new fetchproxy repo).

End-user impact:
- Users install the new \`fetchproxy\` Chrome extension once
- Add port 37149 to fetchproxy via the extension popup
- Approve the "opentable-mcp on opentable.com" trust prompt
- Booking flow works identically

No tool surface changes. No protocol changes that the tests can see. Live-verified: \`scripts/probe-find-slots.ts\` returns the expected output.

## Test plan

- [x] Unit tests pass (\`ws-server.test.ts\` removed; covered upstream)
- [x] Build clean
- [x] Live: probe-find-slots returns slots via the new fetchproxy extension
- [ ] Live: probe-book-cancel works end-to-end (run during release verification)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
BODY
)"
```

---

## Self-Review

Walking the spec section-by-section vs. the plan:

**README §"Why"** — covered by the existence of the migration in Task 11 (opentable-mcp keeps working through the cutover).

**README §"Architecture"** — three packages match (`@fetchproxy/server` Task 2, `extension-core` Tasks 3-7, `extension-chrome` Task 8, protocol Task 1).

**README §"Scope (in-scope)"** — every bullet has a task:
- `fetch(url, init)` from MCP server → Task 2 (server), Task 5 (background routing), Task 6 (content fetcher)
- Tab-pinned routing → Task 3 (url-match helpers), Task 5 (background.ts tab routing)
- Status indicators → Task 7 (popup)
- Multi-MCP support → Task 5 (connections map keyed on port), Task 7 (popup configured-ports UI)
- Chrome MV3 → Task 8

**README §"Out of scope"** — DOM automation, eval_js, cookie exfiltration, headless, cross-origin proxy: none of these have tasks (correctly). The protocol task (Task 1) only validates `op: "fetch"`.

**README §"Cross-browser strategy"** — Chrome only in Phase 1 (this plan); Safari is Phase 2 explicitly out of this plan.

**PROTOCOL.md** — every frame type covered by Task 1 (validators). Lifecycle handled in Task 5 (background.ts state machine).

**SECURITY.md T1-T10:**
- T1 (malicious local process) — Task 4 (trust-store), Task 5 (trust gate before ready), Task 7 (prompt UI)
- T2 (webpage drive-by) — Task 2 (server-side verifyClient Origin check)
- T3 (compromised MCP / domain scope) — Task 3 (url-match helpers), Task 5 (enforcement in handleFetchRequest)
- T4 (unknown MCP) — Task 7 (high-risk-TLD warning in prompt)
- T5 (lateral via navigation) — non-issue per spec; no task needed
- T6 (crafted frame / SW compromise) — Task 1 (validators reject prototype-pollution and unknown types)
- T7 (CSRF token exposure) — documented in spec; no code change in Phase 1
- T8 (MCP impersonation / TOCTOU) — Task 4 (major-version re-prompt logic)
- T9 (cross-MCP id collision) — Task 2 (per-connection state)
- T10 (extension supply chain) — addressed in Task 11 (publish + signing); no code

All ten threats have at least one defensive task. Two open questions deferred (per the user's direction).

**Placeholder scan:** No TBDs. Task 9 has manual steps (it's the smoke test); each step is an exact command or click. Task 11 has a "you decide PR vs. push to main" branch — that's an actual decision point, not a placeholder.

**Type consistency:**
- `McpIdentity` / `TrustedMcp` defined in Task 4, referenced consistently in Tasks 5, 7.
- `FetchInit` / `FetchResult` / `FetchproxyServerOptions` defined in Task 2, consistent in Task 10's adapter.
- `Frame` / `HelloServer` / `FetchRequest` from `@fetchproxy/protocol` (Task 1), consistent in Tasks 2, 5.
- `ConfiguredPort` defined in Task 5, consistent in Task 7.

No mismatches found.

**Gaps I deliberately left:**

1. **Auto-merge workflow** — not in this plan. The opentable-mcp pattern of dropping in `.github/workflows/auto-merge.yml` can be a Phase 1.5 task once the repo has its first PR.
2. **CI workflow (`npm test` on push)** — same, deferred.
3. **Chrome Web Store submission** — way out of scope; placeholder icons + unpacked-load only for v1.

---

Plan complete and saved to `docs/superpowers/plans/2026-05-21-phase-1-chrome-mvp.md`. Two execution options:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, two-stage review between, fast iteration. Right fit because most tasks are mechanical TS scaffolding with clear specs; Task 9 (the smoke test) is controller-driven.

**2. Inline Execution** — execute tasks in this session using executing-plans, batch with checkpoints.

Which?
