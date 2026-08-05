import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
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
    expect(parseCliArgs(['trust', 'list'])).toEqual({ kind: 'trust', action: 'list', json: false });
    expect(parseCliArgs(['trust', 'list', '--json'])).toEqual({
      kind: 'trust',
      action: 'list',
      json: true,
    });
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
    // Two intentions in one command: refuse rather than guess the broader one.
    expect(() => parseCliArgs(['trust', 'clear', 'opentable-mcp', '--all'])).toThrow(/not both/);
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
    await runTrust({ kind: 'trust', action: 'list', json: false }, ioAdapter(rec2), dir);
    expect(rec2.out.join('\n')).toMatch(/no extension pins/i);
  });

  it('lists what is pinned, and says plainly when nothing is', async () => {
    const rec = io();
    expect(await runTrust({ kind: 'trust', action: 'list', json: false }, ioAdapter(rec), dir)).toBe(EXIT.OK);
    expect(rec.out.join('\n')).toMatch(/no extension pins/i);

    await writeFile(join(dir, 'opentable-mcp.extension-trust.json'), PIN);
    const rec2 = io();
    await runTrust({ kind: 'trust', action: 'list', json: false }, ioAdapter(rec2), dir);
    const listed = rec2.out.join('\n');
    expect(listed).toContain('opentable-mcp');
    expect(listed).toContain('QUFB');
    expect(listed.startsWith('[')).toBe(false);

    const rec3 = io();
    await runTrust({ kind: 'trust', action: 'list', json: true }, ioAdapter(rec3), dir);
    expect(JSON.parse(rec3.out.join('\n'))[0].pinFile).toBe('opentable-mcp');
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

  it('lists a scoped MCP under a name clear will accept', async () => {
    // The listing is what an operator copies into `clear`. Printing the file
    // stem meant handing them `@fetchproxy_example-mcp` — the one string that
    // comes back "unsafe serverName", at the moment they are already locked out.
    await writeFile(join(dir, '@fetchproxy_example-mcp.extension-trust.json'), PIN);
    const rec = io();
    await runTrust({ kind: 'trust', action: 'list', json: false }, ioAdapter(rec), dir);
    expect(rec.out.join('\n')).toContain('@fetchproxy/example-mcp');

    const listed = rec.out.join('\n').split(/\s+/)[0]!;
    const rec2 = io();
    expect(
      await runTrust({ kind: 'trust', action: 'clear', serverName: listed }, ioAdapter(rec2), dir),
    ).toBe(EXIT.OK);
    expect(rec2.err.join('\n')).toMatch(/cleared/i);
  });

  it('does not invent a name it cannot recover, and clears it anyway', async () => {
    // `_` is legal on both sides of a scope's `/`, so `@my_org/tool-mcp` and
    // `@my/org_tool-mcp` share one stem and neither is recoverable from it.
    // Printing a guess would name a package that may not exist; the stem is
    // shown instead, and `clear` accepts it so the listing stays usable.
    await writeFile(join(dir, '@my_org_tool-mcp.extension-trust.json'), PIN);
    const rec = io();
    await runTrust({ kind: 'trust', action: 'list', json: false }, ioAdapter(rec), dir);
    expect(rec.out.join('\n')).toContain('@my_org_tool-mcp');
    expect(rec.out.join('\n')).not.toContain('@my/org_tool-mcp');

    const rec2 = io();
    expect(
      await runTrust(
        { kind: 'trust', action: 'clear', serverName: '@my_org_tool-mcp' },
        ioAdapter(rec2),
        dir,
      ),
    ).toBe(EXIT.OK);
    const rec3 = io();
    await runTrust({ kind: 'trust', action: 'list', json: false }, ioAdapter(rec3), dir);
    expect(rec3.out.join('\n')).toMatch(/no extension pins/i);
  });

  it('surfaces a filesystem failure as itself, not as "no such pin"', async () => {
    // The fallback used to be reached by catching ANY throw, so a permissions
    // problem on the identity directory was reported as a missing pin —
    // sending the reader after a file that is right there.
    if (process.getuid?.() === 0) return; // root ignores the mode
    await writeFile(join(dir, '@fetchproxy_example-mcp.extension-trust.json'), PIN);
    await chmod(dir, 0o500);
    try {
      await expect(
        runTrust(
          { kind: 'trust', action: 'clear', serverName: '@fetchproxy/example-mcp' },
          ioAdapter(io()),
          dir,
        ),
      ).rejects.toThrow(/EACCES|EPERM/);
    } finally {
      await chmod(dir, 0o700);
    }
  });

  it('clears a scoped MCP, whose pin file name is not its server name', async () => {
    // `@fetchproxy/example-mcp` is stored as `@fetchproxy_example-mcp.…`, and
    // feeding that filename back in as a server name is rejected as unsafe —
    // so listing and clearing have to agree about which string is which.
    await writeFile(join(dir, '@fetchproxy_example-mcp.extension-trust.json'), PIN);
    const rec = io();
    expect(
      await runTrust(
        { kind: 'trust', action: 'clear', serverName: '@fetchproxy/example-mcp' },
        ioAdapter(rec),
        dir,
      ),
    ).toBe(EXIT.OK);
    expect(rec.err.join('\n')).toMatch(/cleared/i);

    const rec2 = io();
    await runTrust({ kind: 'trust', action: 'list', json: false }, ioAdapter(rec2), dir);
    expect(rec2.out.join('\n')).toMatch(/no extension pins/i);
  });

  it('clears every pin with --all even when one is scoped', async () => {
    // --all used to abort partway on the first scoped name, leaving the fleet
    // half-cleared and the operator believing it was done.
    await writeFile(join(dir, '@fetchproxy_example-mcp.extension-trust.json'), PIN);
    await writeFile(join(dir, 'opentable-mcp.extension-trust.json'), PIN);
    const rec = io();
    expect(await runTrust({ kind: 'trust', action: 'clear', all: true }, ioAdapter(rec), dir)).toBe(
      EXIT.OK,
    );
    const rec2 = io();
    await runTrust({ kind: 'trust', action: 'list', json: false }, ioAdapter(rec2), dir);
    expect(rec2.out.join('\n')).toMatch(/no extension pins/i);
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
    await runTrust({ kind: 'trust', action: 'list', json: false }, ioAdapter(rec), dir);
    expect(rec.out.join('\n')).toContain('resy-mcp');
    expect(rec.out.join('\n')).not.toContain('opentable-mcp');
  });
});
