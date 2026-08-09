import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import * as hello from '../src/background/hello.js';
import * as badge from '../src/background/badge.js';
import * as pendingRecords from '../src/background/pending-records.js';

/**
 * The background split (#226) carved `background.ts` into purpose-shaped
 * modules. Several helpers that were file-private before the split picked up
 * an `export` on the way out even though nothing outside their own module
 * calls them, which quietly widens each module's surface.
 *
 * Value exports are asserted through the ES module namespace. Interfaces and
 * type aliases are erased at runtime and so are invisible there — and this
 * package's `tsconfig.json` includes only `src`, so `tsc -b` never reads
 * `tests/` either and a stray `export interface` cannot be caught by a type
 * error. Those are asserted against the module source text instead.
 */

/** Names declared with `export interface` / `export type` in a module's source. */
function exportedTypeNames(relativePath: string): string[] {
  const source = readFileSync(fileURLToPath(new URL(relativePath, import.meta.url)), 'utf8');
  return [...source.matchAll(/^export (?:interface|type) (\w+)/gm)].map((m) => m[1]).sort();
}

describe('background module surfaces', () => {
  it('hello.ts exports only the decision function its callers import', () => {
    // sameDomainSet / DEFAULT_CAPABILITIES / effectiveCapabilities /
    // declaredScope are helpers of handleServerHello, called nowhere else.
    expect(Object.keys(hello).sort()).toEqual(['handleServerHello']);
  });

  it('hello.ts exports only the two types its callers name', () => {
    // DeclaredScope is the return type of the file-local declaredScope helper;
    // no caller outside hello.ts ever names it.
    expect(exportedTypeNames('../src/background/hello.ts')).toEqual([
      'HandleHelloDeps',
      'HandleHelloResult',
    ]);
  });

  it('badge.ts exports only the four badge transitions its callers import', () => {
    // syncBadge is the internal repaint that the four transitions delegate to.
    expect(Object.keys(badge).sort()).toEqual([
      'clearPairPendingBadge',
      'flashActivity',
      'setConnectionStatus',
      'setPairPendingBadge',
    ]);
  });

  it('pending-records.ts exports one function at runtime; the rest are types', () => {
    expect(Object.keys(pendingRecords).sort()).toEqual(['applyNeedsPairRecord']);
  });

  it('pending-records.ts keeps PendingRecordBase file-local', () => {
    // server-hello.ts constructs both record kinds and so names both subtypes,
    // but nothing outside this file names the shared base they extend.
    expect(exportedTypeNames('../src/background/pending-records.ts')).toEqual([
      'AnyPendingRecord',
      'PendingPairRecord',
      'PendingScopeUpdateRecord',
    ]);
  });
});
