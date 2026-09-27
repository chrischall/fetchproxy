import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, readdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateEd25519, generateX25519 } from '@fetchproxy/protocol';
import {
  EXTENSION_PINS_ENV,
  EXTENSION_PINS_FILE_VERSION,
  ExtensionPinsError,
  decideManagedExtensionTrust,
  evaluateManagedExtensionTrust,
  extensionPinsPath,
  parseExtensionPins,
  readExtensionPins,
  resolveExtensionPinsMode,
  type ExtensionPinSet,
} from '../src/extension-pins.js';
import { fileExtensionTrust } from '../src/extension-trust.js';
import * as publicApi from '../src/index.js';

/**
 * A3 (account-level bridge pairing, D4): a HOST-MANAGED pin set.
 *
 * The first-use pin (`extension-trust.ts`) is one value per MCP, taken from
 * whichever extension completes a handshake first. A hosting provider that
 * already knows which browsers belong to an account needs to PROVIDE the set
 * instead, so no child ever trusts on first use and a second browser works
 * without an operator.
 *
 * Invariants these tests hold (spec §4.9, I-13 child half):
 *  - an extension is accepted only when ONE entry matches BOTH its X25519 and
 *    its Ed25519 key — never either alone;
 *  - the set is read fresh on every handshake, never cached;
 *  - managed mode never writes a trust file and never falls back to first use;
 *  - a missing, unreadable or malformed set refuses everything (fail closed),
 *    and the refusal names the path but never a key.
 */

const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');

async function ext(): Promise<{ x25519Pub: string; ed25519Pub: string }> {
  const x = await generateX25519();
  const ed = await generateEd25519();
  return { x25519Pub: b64(x.publicKey), ed25519Pub: b64(ed.publicKey) };
}

function hello(e: { x25519Pub: string; ed25519Pub: string }) {
  return { identityX25519Pub: e.x25519Pub, identityEd25519Pub: e.ed25519Pub };
}

function setOf(...entries: { x25519Pub: string; ed25519Pub: string; label?: string }[]) {
  return { v: 1, managed: true, extensions: entries };
}

const KEY_A = b64(new Uint8Array(32).fill(1));
const KEY_B = b64(new Uint8Array(32).fill(2));

describe('parseExtensionPins', () => {
  it('exports the file version it parses', () => {
    expect(EXTENSION_PINS_FILE_VERSION).toBe(1);
    // A host validates what it writes with the same function, so both must be
    // on the public surface.
    expect(publicApi.EXTENSION_PINS_FILE_VERSION).toBe(1);
    expect(publicApi.parseExtensionPins).toBe(parseExtensionPins);
  });

  it('accepts the documented shape, with and without labels', () => {
    const parsed = parseExtensionPins(
      JSON.stringify({
        v: 1,
        managed: true,
        managedBy: 'mcp-host',
        extensions: [
          { x25519Pub: KEY_A, ed25519Pub: KEY_B, label: 'Chrome on laptop' },
          { x25519Pub: KEY_B, ed25519Pub: KEY_A },
        ],
      }),
    );
    expect(parsed).toEqual<ExtensionPinSet>({
      v: 1,
      managed: true,
      managedBy: 'mcp-host',
      extensions: [
        { x25519Pub: KEY_A, ed25519Pub: KEY_B, label: 'Chrome on laptop' },
        { x25519Pub: KEY_B, ed25519Pub: KEY_A },
      ],
    });
  });

  it('accepts an empty set — every token revoked is a legitimate, fail-closed state', () => {
    expect(parseExtensionPins(JSON.stringify(setOf())).extensions).toEqual([]);
  });

  it.each([
    ['not JSON', '{nope'],
    ['not an object', '[]'],
    ['null', 'null'],
    ['the wrong version', JSON.stringify({ ...setOf(), v: 2 })],
    ['no version', JSON.stringify({ managed: true, extensions: [] })],
    ['managed false', JSON.stringify({ ...setOf(), managed: false })],
    ['managed missing', JSON.stringify({ v: 1, extensions: [] })],
    ['extensions missing', JSON.stringify({ v: 1, managed: true })],
    ['extensions not an array', JSON.stringify({ v: 1, managed: true, extensions: {} })],
    ['an entry that is not an object', JSON.stringify(setOf('x' as never))],
    ['an entry with no ed25519Pub', JSON.stringify(setOf({ x25519Pub: KEY_A } as never))],
    ['an entry with no x25519Pub', JSON.stringify(setOf({ ed25519Pub: KEY_A } as never))],
    ['a key that is not base64', JSON.stringify(setOf({ x25519Pub: '!!!!', ed25519Pub: KEY_A }))],
    [
      'a key that is not 32 bytes',
      JSON.stringify(setOf({ x25519Pub: b64(new Uint8Array(31)), ed25519Pub: KEY_A })),
    ],
    [
      'a key in non-canonical base64',
      JSON.stringify(setOf({ x25519Pub: KEY_A.replace(/=+$/, ''), ed25519Pub: KEY_B })),
    ],
    ['an empty key', JSON.stringify(setOf({ x25519Pub: '', ed25519Pub: KEY_A }))],
    [
      'a label that is not a string',
      JSON.stringify(setOf({ x25519Pub: KEY_A, ed25519Pub: KEY_B, label: 7 } as never)),
    ],
    ['a managedBy that is not a string', JSON.stringify({ ...setOf(), managedBy: 3 })],
  ])('refuses %s', (_name, text) => {
    let caught: unknown;
    try {
      parseExtensionPins(text);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ExtensionPinsError);
    expect((caught as ExtensionPinsError).code).toBe('EXTENSION_PINS_MALFORMED');
  });

  it('never echoes key material in its error', () => {
    // The refusal is logged by a child the host runs; a message that quotes
    // the file would put the account's browser keys into its logs.
    const secretish = b64(new Uint8Array(31).fill(9));
    try {
      parseExtensionPins(JSON.stringify(setOf({ x25519Pub: secretish, ed25519Pub: KEY_A })));
      expect.unreachable();
    } catch (e) {
      expect(String((e as Error).message)).not.toContain(secretish);
      expect(String((e as Error).message)).not.toContain(KEY_A);
    }
  });
});

describe('decideManagedExtensionTrust', () => {
  it('accepts every extension in the set', async () => {
    const e1 = await ext();
    const e2 = await ext();
    const set = parseExtensionPins(JSON.stringify(setOf(e1, e2)));
    for (const e of [e1, e2]) {
      expect(
        decideManagedExtensionTrust({ set, hello: hello(e), serverName: 'opentable-mcp' }).decision,
      ).toBe('pinned');
    }
  });

  it('refuses an extension that is not in the set', async () => {
    const e1 = await ext();
    const e3 = await ext();
    const set = parseExtensionPins(JSON.stringify(setOf(e1)));
    const out = decideManagedExtensionTrust({ set, hello: hello(e3), serverName: 'opentable-mcp' });
    expect(out.decision).toBe('refused');
  });

  it('refuses each half-match: both keys from ONE entry, never either alone', async () => {
    // The both-or-neither test. A mix of E1's X25519 and E2's Ed25519 is a
    // browser that holds E2's signing key and presents E1's agreement key —
    // it would sign a `ready` that verifies, so the pairing check is the
    // whole of what refuses it.
    const e1 = await ext();
    const e2 = await ext();
    const set = parseExtensionPins(JSON.stringify(setOf(e1, e2)));
    const mixes = [
      { x25519Pub: e1.x25519Pub, ed25519Pub: e2.ed25519Pub },
      { x25519Pub: e2.x25519Pub, ed25519Pub: e1.ed25519Pub },
    ];
    for (const m of mixes) {
      expect(
        decideManagedExtensionTrust({ set, hello: hello(m), serverName: 'opentable-mcp' }).decision,
      ).toBe('refused');
    }
    // …and a match on one key with a stranger's other.
    const stranger = await ext();
    for (const m of [
      { x25519Pub: e1.x25519Pub, ed25519Pub: stranger.ed25519Pub },
      { x25519Pub: stranger.x25519Pub, ed25519Pub: e1.ed25519Pub },
    ]) {
      expect(
        decideManagedExtensionTrust({ set, hello: hello(m), serverName: 'opentable-mcp' }).decision,
      ).toBe('refused');
    }
  });

  it('refuses everything under an empty set', async () => {
    const set = parseExtensionPins(JSON.stringify(setOf()));
    expect(
      decideManagedExtensionTrust({ set, hello: hello(await ext()), serverName: 'x-mcp' }).decision,
    ).toBe('refused');
  });

  it('never answers first-use or replace — there is no trust-on-first-use in managed mode', async () => {
    const e1 = await ext();
    const set = parseExtensionPins(JSON.stringify(setOf(e1)));
    for (const h of [hello(e1), hello(await ext())]) {
      expect(['pinned', 'refused']).toContain(
        decideManagedExtensionTrust({ set, hello: h, serverName: 'x-mcp' }).decision,
      );
    }
  });
});

describe('the managed pin-set file', () => {
  let dir: string;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    delete process.env[EXTENSION_PINS_ENV];
    delete process.env.FETCHPROXY_TRUST_NEW_EXTENSION;
    vi.restoreAllMocks();
  });

  it('lives at <trustDir>/<serverName>.extension-pins.json', () => {
    dir = mkdtempSync(join(tmpdir(), 'fp-pins-'));
    expect(extensionPinsPath('opentable-mcp', dir)).toBe(join(dir, 'opentable-mcp.extension-pins.json'));
    expect(extensionPinsPath('@fetchproxy/example-mcp', dir)).toBe(
      join(dir, '@fetchproxy_example-mcp.extension-pins.json'),
    );
  });

  it('reports a missing file as EXTENSION_PINS_MISSING, naming the path', async () => {
    dir = mkdtempSync(join(tmpdir(), 'fp-pins-'));
    const err = await readExtensionPins('opentable-mcp', dir).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ExtensionPinsError);
    expect((err as ExtensionPinsError).code).toBe('EXTENSION_PINS_MISSING');
    expect((err as Error).message).toContain(extensionPinsPath('opentable-mcp', dir));
  });

  it('reports a malformed file as EXTENSION_PINS_MALFORMED, naming the path', async () => {
    dir = mkdtempSync(join(tmpdir(), 'fp-pins-'));
    writeFileSync(extensionPinsPath('opentable-mcp', dir), '{"v":1,');
    const err = await readExtensionPins('opentable-mcp', dir).catch((e: unknown) => e);
    expect((err as ExtensionPinsError).code).toBe('EXTENSION_PINS_MALFORMED');
    expect((err as Error).message).toContain(extensionPinsPath('opentable-mcp', dir));
  });

  it('evaluates to a refusal, never a throw, when the set cannot be had', async () => {
    dir = mkdtempSync(join(tmpdir(), 'fp-pins-'));
    const port = fileExtensionTrust({
      serverName: 'opentable-mcp',
      trustDir: dir,
      allowNew: false,
      extensionPins: 'managed',
    });
    const e1 = await ext();
    const missing = await evaluateManagedExtensionTrust(port.managed!, hello(e1), 'opentable-mcp');
    expect(missing).toMatchObject({ decision: 'refused', code: 'EXTENSION_PINS_MISSING' });
    writeFileSync(extensionPinsPath('opentable-mcp', dir), 'garbage');
    const malformed = await evaluateManagedExtensionTrust(port.managed!, hello(e1), 'opentable-mcp');
    expect(malformed).toMatchObject({ decision: 'refused', code: 'EXTENSION_PINS_MALFORMED' });
  });

  it('is read afresh on every call — a changed file needs no restart', async () => {
    dir = mkdtempSync(join(tmpdir(), 'fp-pins-'));
    const e1 = await ext();
    const e2 = await ext();
    const port = fileExtensionTrust({
      serverName: 'opentable-mcp',
      trustDir: dir,
      allowNew: false,
      extensionPins: 'managed',
    });
    writeFileSync(extensionPinsPath('opentable-mcp', dir), JSON.stringify(setOf(e1)));
    expect((await evaluateManagedExtensionTrust(port.managed!, hello(e2), 'm')).decision).toBe(
      'refused',
    );
    writeFileSync(extensionPinsPath('opentable-mcp', dir), JSON.stringify(setOf(e1, e2)));
    expect((await evaluateManagedExtensionTrust(port.managed!, hello(e2), 'm')).decision).toBe(
      'pinned',
    );
    writeFileSync(extensionPinsPath('opentable-mcp', dir), JSON.stringify(setOf(e2)));
    expect((await evaluateManagedExtensionTrust(port.managed!, hello(e1), 'm')).decision).toBe(
      'refused',
    );
  });

  it('gives a managed port that never writes and never allows a new identity', async () => {
    dir = mkdtempSync(join(tmpdir(), 'fp-pins-'));
    const port = fileExtensionTrust({
      serverName: 'opentable-mcp',
      trustDir: dir,
      allowNew: true,
      extensionPins: 'managed',
    });
    expect(port.managed).toBeDefined();
    expect(port.allowNew).toBe(false);
    await expect(
      port.write({ identityX25519Pub: KEY_A, identityEd25519Pub: KEY_B, pinnedAt: 1 }),
    ).rejects.toThrow(/managed/);
    // The first-use pin is not consulted either: a stale one on disk must not
    // be able to answer for a managed MCP.
    writeFileSync(
      join(dir, 'opentable-mcp.extension-trust.json'),
      JSON.stringify({ identityX25519Pub: KEY_A, identityEd25519Pub: KEY_B, pinnedAt: 1 }),
    );
    expect(await port.read()).toBeNull();
    expect(readdirSync(dir)).toEqual(['opentable-mcp.extension-trust.json']);
  });

  it('leaves an unmanaged port exactly as it was', () => {
    dir = mkdtempSync(join(tmpdir(), 'fp-pins-'));
    const port = fileExtensionTrust({ serverName: 'opentable-mcp', trustDir: dir, allowNew: true });
    expect(port.managed).toBeUndefined();
    expect(port.allowNew).toBe(true);
  });
});

describe('resolveExtensionPinsMode', () => {
  afterEach(() => vi.restoreAllMocks());

  it('is first-use when neither the option nor the environment says managed', () => {
    expect(resolveExtensionPinsMode(undefined, {})).toBe('first-use');
    expect(resolveExtensionPinsMode(undefined, { [EXTENSION_PINS_ENV]: '' })).toBe('first-use');
  });

  it('is managed when the option or the environment says so', () => {
    expect(resolveExtensionPinsMode('managed', {})).toBe('managed');
    expect(resolveExtensionPinsMode(undefined, { [EXTENSION_PINS_ENV]: 'managed' })).toBe('managed');
  });

  it('fails closed on a value it does not recognise, and says so', () => {
    // A host that set the variable has declared that it manages the pins. A
    // typo must not quietly hand the child back to trust on first use.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(resolveExtensionPinsMode(undefined, { [EXTENSION_PINS_ENV]: 'Managed ' })).toBe('managed');
    expect(resolveExtensionPinsMode(undefined, { [EXTENSION_PINS_ENV]: '1' })).toBe('managed');
    expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).toContain(EXTENSION_PINS_ENV);
  });
});
