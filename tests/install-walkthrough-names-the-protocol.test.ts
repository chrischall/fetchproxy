import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROTOCOL_VERSION } from '@fetchproxy/protocol';
import { FetchproxyProtocolVersionError, protocolVersionCloseReason } from '@fetchproxy/server';

/**
 * The install walkthrough states which extension pairs with which packages.
 * Since the extension moved to nullnet-app/contextmint-bridge it versions on
 * its own release line, so the fact the walkthrough has to get right is the
 * PROTOCOL number — the one contract the two halves still share — and the
 * refusal a reader meets when they get it wrong.
 *
 * A sentence like that is exactly the kind that goes stale: the next major
 * moves `PROTOCOL_VERSION` and the words the refusal uses, and nothing about a
 * paragraph in a README fails when it does. So what the walkthrough prints is
 * asserted against what the running code refuses with — `PROTOCOL_VERSION`
 * itself, and a real {@link FetchproxyProtocolVersionError}'s own message —
 * rather than against literals typed a second time here, which would just be
 * the same staleness in a test file.
 *
 * What this does NOT check is whether the prose is any good. It checks that a
 * reader who follows the walkthrough meets the same protocol number and the
 * same error string the code will actually hand them. The extension's own
 * sideload walkthrough is guarded in the bridge repo.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path: string): string => readFileSync(join(ROOT, path), 'utf8');

/**
 * The section under `heading`, up to the next heading of the same level.
 *
 * Returns the whole tail for the last section in a file, and `null` when the
 * heading is not there at all — which is a failure below, not a pass: a
 * renamed heading must break this suite rather than silently empty it.
 */
function section(markdown: string, heading: string): string | null {
  const level = heading.match(/^#+/)?.[0];
  if (!level) throw new Error(`not a heading: ${heading}`);
  const start = markdown.indexOf(`${heading}\n`);
  if (start === -1) return null;
  const rest = markdown.slice(start + heading.length);
  const next = rest.search(new RegExp(`\\n${level}[^#]`));
  return next === -1 ? rest : rest.slice(0, next);
}

/** The sentence a refused MCP actually prints when the EXTENSION is behind. */
const REFUSAL = new FetchproxyProtocolVersionError({
  ourVersion: PROTOCOL_VERSION,
  theirVersion: PROTOCOL_VERSION - 1,
  peer: 'extension',
}).message;

/** "protocol version mismatch" — the words a person will search for. */
const REFUSAL_PHRASE = REFUSAL.split(':')[0];

describe('the install walkthrough names the protocol the code refuses outside of', () => {
  it('read the refusal the walkthrough quotes', () => {
    // Guard: every assertion below is derived from this message, so a change
    // in its shape must fail here rather than make the rest vacuous.
    expect(REFUSAL_PHRASE).toBe('protocol version mismatch');
    expect(REFUSAL).toContain(`fetchproxy protocol ${PROTOCOL_VERSION}`);
  });

  const install = (): string => {
    const body = section(read('README.md'), '## Install');
    expect(body, 'no ## Install section in README.md').not.toBeNull();
    // Belt and braces on the extractor: a section that shrank to nothing must
    // not pass the positive checks below by accident.
    expect(body!.length).toBeGreaterThan(200);
    return body!;
  };

  it('pairs the two halves by protocol, not by a shared version', () => {
    const body = install();
    expect(body).toContain(`protocol ${PROTOCOL_VERSION}`);
    expect(body).toContain('ContextMint Bridge');
    expect(body).toContain('https://github.com/nullnet-app/contextmint-bridge/releases');
  });

  it('makes the reload a requirement, and names what it prevents', () => {
    const body = install();
    expect(body.toLowerCase()).toContain('reload');
    // The failure it prevents, in the words the person will see — not a
    // paraphrase. A stale extension is refused at the hello, so "reload after
    // updating" is the difference between a working bridge and every call
    // failing at once, and quoting the message is what lets a reader match
    // the two.
    expect(body).toContain(REFUSAL_PHRASE);
  });

  it('quotes the MCP-side refusal verbatim rather than paraphrasing it', () => {
    // The close reason and the thrown error are what the reader will have in
    // front of them — a log line and a tool result. A paraphrase is worse than
    // no quote at all here, because it is the thing they would search for and
    // not find. Both come from the running code, so a reworded message fails
    // this and takes the walkthrough with it.
    const body = install();
    expect(body).toContain(
      protocolVersionCloseReason({
        ourVersion: PROTOCOL_VERSION,
        theirVersion: PROTOCOL_VERSION - 1,
        peer: 'extension',
      }),
    );
    // The remedy half of the thrown error, from the em dash onwards.
    expect(body).toContain(REFUSAL.slice(REFUSAL.indexOf('— ') + 2));
  });
});
