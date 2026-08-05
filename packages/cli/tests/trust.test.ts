import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCliArgs } from '../src/args.js';
import { runTrust } from '../src/verbs/trust.js';
import { EXIT } from '../src/output.js';

/**
 * #208 gives the MCP a pin on the extension's identity, which means a browser
 * re-install can lock every MCP out. The escape hatches have to be findable:
 * an environment variable for MCPs whose source you don't own, and this — for
 * seeing what is pinned and dropping one on purpose.
 */

function io(): { out: string[]; err: string[] } & {
  out_: (s: string) => void;
  err_: (s: string) => void;
} {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, out_: (s) => out.push(s), err_: (s) => err.push(s) };
}

function ioAdapter(rec: ReturnType<typeof io>) {
  return { out: rec.out_, err: rec.err_ };
}

const PIN = JSON.stringify({
  identityX25519Pub: 'QUFB',
  identityEd25519Pub: 'QkJC',
  pinnedAt: 1_700_000_000_000,
});

describe('fpx trust', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'fpx-trust-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('parses list and clear', () => {
    expect(parseCliArgs(['trust', 'list'])).toEqual({ kind: 'trust', action: 'list' });
    expect(parseCliArgs(['trust', 'clear', 'opentable-mcp'])).toEqual({
      kind: 'trust',
      action: 'clear',
      serverName: 'opentable-mcp',
    });
  });

  it('refuses a bare clear — clearing everything has to be said, not omitted', () => {
    expect(() => parseCliArgs(['trust', 'clear'])).toThrow(/server/i);
    expect(parseCliArgs(['trust', 'clear', '--all'])).toEqual({
      kind: 'trust',
      action: 'clear',
      all: true,
    });
  });

  it('clears every pin with --all, which is what an extension re-install needs', async () => {
    await writeFile(join(dir, 'opentable-mcp.extension-trust.json'), PIN);
    await writeFile(join(dir, 'resy-mcp.extension-trust.json'), PIN);
    const rec = io();
    expect(await runTrust({ kind: 'trust', action: 'clear', all: true }, ioAdapter(rec), dir)).toBe(
      EXIT.OK,
    );
    expect(rec.err.join('\n')).toMatch(/cleared 2 extension pin/);

    const rec2 = io();
    await runTrust({ kind: 'trust', action: 'list' }, ioAdapter(rec2), dir);
    expect(rec2.out.join('\n')).toMatch(/no extension pins/i);
  });

  it('lists what is pinned, and says plainly when nothing is', async () => {
    const rec = io();
    expect(await runTrust({ kind: 'trust', action: 'list' }, ioAdapter(rec), dir)).toBe(EXIT.OK);
    expect(rec.out.join('\n')).toMatch(/no extension pins/i);

    await writeFile(join(dir, 'opentable-mcp.extension-trust.json'), PIN);
    const rec2 = io();
    await runTrust({ kind: 'trust', action: 'list' }, ioAdapter(rec2), dir);
    const listed = rec2.out.join('\n');
    expect(listed).toContain('opentable-mcp');
    expect(listed).toContain('QUFB');
  });

  it('clears one pin and reports whether there was one', async () => {
    await writeFile(join(dir, 'opentable-mcp.extension-trust.json'), PIN);
    const rec = io();
    expect(
      await runTrust(
        { kind: 'trust', action: 'clear', serverName: 'opentable-mcp' },
        ioAdapter(rec),
        dir,
      ),
    ).toBe(EXIT.OK);
    expect(rec.err.join('\n')).toMatch(/cleared/i);

    const rec2 = io();
    await runTrust(
      { kind: 'trust', action: 'clear', serverName: 'opentable-mcp' },
      ioAdapter(rec2),
      dir,
    );
    expect(rec2.err.join('\n')).toMatch(/nothing pinned/i);
  });

  it('leaves the other MCPs pins alone', async () => {
    await writeFile(join(dir, 'opentable-mcp.extension-trust.json'), PIN);
    await writeFile(join(dir, 'resy-mcp.extension-trust.json'), PIN);
    await runTrust(
      { kind: 'trust', action: 'clear', serverName: 'opentable-mcp' },
      ioAdapter(io()),
      dir,
    );
    const rec = io();
    await runTrust({ kind: 'trust', action: 'list' }, ioAdapter(rec), dir);
    expect(rec.out.join('\n')).toContain('resy-mcp');
    expect(rec.out.join('\n')).not.toContain('opentable-mcp');
  });
});
