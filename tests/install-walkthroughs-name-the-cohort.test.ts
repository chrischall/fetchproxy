import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROTOCOL_VERSION } from '@fetchproxy/protocol';
import { FetchproxyProtocolVersionError, protocolVersionCloseReason } from '@fetchproxy/server';

/**
 * The two install walkthroughs state a fact about the COHORT — which extension
 * pairs with which package major — and Task 6.5 put it there because 3.0.0 is
 * the first release where installing one half and not the other stops the
 * bridge dead rather than degrading.
 *
 * A sentence like that is exactly the kind that goes stale: the next major
 * moves `PROTOCOL_VERSION` and the version the refusal names, and nothing
 * about a paragraph in a README fails when it does. So the numbers the
 * walkthroughs print are asserted against the numbers the running code
 * refuses with — `PROTOCOL_VERSION` itself, and the version parsed back out
 * of a real {@link FetchproxyProtocolVersionError}'s own message — rather than
 * against literals typed a second time here, which would just be the same
 * staleness in a test file.
 *
 * What this does NOT check is whether the prose is any good. It checks that a
 * reader who follows the walkthrough meets the same version pairing, the same
 * protocol number and the same error string the code will actually hand them.
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

/**
 * The release at which this protocol lands, taken from the sentence a refused
 * MCP actually prints. `MIN_VERSION` in `server/src/session-ready.ts` is
 * module-private by design, and this is the surface it exists to produce.
 */
const REFUSAL = new FetchproxyProtocolVersionError({
  ourVersion: PROTOCOL_VERSION,
  theirVersion: PROTOCOL_VERSION - 1,
  peer: 'extension',
}).message;

const COHORT_VERSION = REFUSAL.match(/to (\d+\.\d+\.\d+) or later/)?.[1];
/** "protocol version mismatch" — the words a person will search for. */
const REFUSAL_PHRASE = REFUSAL.split(':')[0];

describe('the install walkthroughs name the cohort the code refuses outside of', () => {
  it('read the refusal the walkthroughs quote', () => {
    // Guard: every assertion below is derived from this message, so a change
    // in its shape must fail here rather than make the rest vacuous.
    expect(COHORT_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(REFUSAL_PHRASE).toBe('protocol version mismatch');
  });

  it('states the same minimum version the extension refuses below', () => {
    // The extension's mirror of that constant, which its own refusal prints
    // and which no test held to the server's copy before now. Read out of the
    // source because `extension-core` is private and does not re-export it;
    // the match is asserted, so a moved declaration fails rather than passes.
    const src = read('packages/extension-core/src/lib/version-mismatch.ts');
    const mirrored = src.match(/MIN_SERVER_VERSION = '(\d+\.\d+\.\d+)'/)?.[1];
    expect(mirrored).toBe(COHORT_VERSION);
  });

  it('is the off-by-one the record states once: package major + 1 = protocol', () => {
    // `frames.ts`'s numbering note and `docs/PROTOCOL.md`'s version table both
    // say package 3.x speaks protocol 4. If that ever stops being true, the
    // "extension 3.x ↔ server 3.x, protocol 4" line below is wrong in a way
    // no reader could catch.
    const major = Number(COHORT_VERSION!.split('.')[0]);
    expect(major + 1).toBe(PROTOCOL_VERSION);
  });

  const WALKTHROUGHS: readonly (readonly [string, string])[] = [
    ['README.md', '## Install'],
    ['packages/extension-chrome/README.md', '## Install (developer / sideload)'],
  ];

  it.each(WALKTHROUGHS)('%s %s pairs the two halves by major', (file, heading) => {
    const body = section(read(file), heading);
    expect(body, `no ${heading} section in ${file}`).not.toBeNull();
    // A section that shrank to nothing would pass the substring checks for the
    // wrong reason only if they were negative; they are positive, so this is
    // belt and braces on the extractor rather than on the prose.
    expect(body!.length).toBeGreaterThan(200);
    const major = COHORT_VERSION!.split('.')[0];
    // The pairing itself: majors move together, and the walkthrough says so in
    // the numbers this build actually holds.
    expect(body).toContain(`${major}.x`);
    expect(body).toContain(`protocol ${PROTOCOL_VERSION}`);
    expect(body).toContain(COHORT_VERSION);
  });

  it.each(WALKTHROUGHS)('%s %s makes the reload a requirement, and names what it prevents', (file, heading) => {
    const body = section(read(file), heading);
    expect(body).not.toBeNull();
    expect(body!.toLowerCase()).toContain('reload');
    // The failure it prevents, in the words the person will see — not a
    // paraphrase. A stale extension is refused at the hello, so "reload after
    // pulling" is the difference between a working bridge and every call
    // failing at once, and quoting the message is what lets a reader match
    // the two.
    expect(body).toContain(REFUSAL_PHRASE);
  });

  it('README.md quotes the MCP-side refusal verbatim rather than paraphrasing it', () => {
    // The close reason and the thrown error are what the reader will have in
    // front of them — a log line and a tool result. A paraphrase is worse than
    // no quote at all here, because it is the thing they would search for and
    // not find. Both come from the running code, so a reworded message fails
    // this and takes the walkthrough with it.
    const body = section(read('README.md'), '## Install')!;
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
