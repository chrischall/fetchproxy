import { describe, it, expect, vi } from 'vitest';
import { FetchproxyHelloRejectedError, protocolErrorFrom } from '@fetchproxy/server';
import { capabilityUnavailableMessage } from '@fetchproxy/protocol';
import { mapBridgeError } from '../src/bridge-errors.js';
import { runHealth } from '../src/verbs/health.js';
import { emptyProfile } from '../src/profiles.js';
import { EXIT, type Io } from '../src/output.js';
import type { VerbServer } from '../src/verbs/fetch.js';

/**
 * #418: a capability this browser cannot serve is the browser's gap, not a
 * version problem and not the MCP's code — fpx has to say so everywhere it
 * can surface: a verb error, the whole-hello refusal, and `fpx health`.
 */
function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = [];
  const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}

describe('fpx — capability unavailable in this browser', () => {
  it('a verb error names the browser and does not suggest a version mismatch', () => {
    const io = memIo();
    const code = mapBridgeError(
      protocolErrorFrom(capabilityUnavailableMessage('download', 'safari')),
      io,
    );
    expect(code).toBe(EXIT.BRIDGE);
    const out = io.errs.join('\n');
    expect(out).toMatch(/capability "download" is not available in this browser \(safari\)/);
    expect(out).toMatch(/this browser \(safari\) cannot serve/);
    expect(out).not.toMatch(/version mismatch/i);
  });

  it('the all-unavailable refusal names the capabilities and the browser', () => {
    const io = memIo();
    const code = mapBridgeError(
      new FetchproxyHelloRejectedError({
        mcpId: 'fpx-shop:1.0.0:abc',
        reason: 'unsupported-capability: download, graphql (not available in this browser)',
        platform: 'safari',
      }),
      io,
    );
    expect(code).toBe(EXIT.BRIDGE);
    const out = io.errs.join('\n');
    expect(out).toMatch(/download, graphql/);
    expect(out).toMatch(/safari/);
    expect(out).not.toMatch(/version mismatch/i);
  });

  it('fpx health lists what the browser cannot serve', async () => {
    const io = memIo();
    const server = {
      listen: vi.fn(async () => {}),
      close: vi.fn(async () => {}),
      bridgeHealth: vi.fn(() => ({
        role: 'host',
        session: { state: 'linked', unavailableCapabilities: ['download'], platform: 'safari' },
      })),
    } as unknown as VerbServer;
    const code = await runHealth(
      { kind: 'health', profile: 'x' },
      emptyProfile(['x.com']),
      io,
      () => server,
    );
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs[0]!).session.unavailableCapabilities).toEqual(['download']);
    expect(io.errs).toContain('unavailable in this browser (safari): download');
  });

  it('fpx health says nothing extra when nothing is missing', async () => {
    const io = memIo();
    const server = {
      listen: vi.fn(async () => {}),
      close: vi.fn(async () => {}),
      bridgeHealth: vi.fn(() => ({
        role: 'host',
        session: { state: 'linked', unavailableCapabilities: [], platform: 'chrome' },
      })),
    } as unknown as VerbServer;
    await runHealth({ kind: 'health', profile: 'x' }, emptyProfile(['x.com']), io, () => server);
    expect(io.errs).toEqual([]);
  });
});
