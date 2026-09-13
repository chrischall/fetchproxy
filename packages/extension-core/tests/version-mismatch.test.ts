import { describe, it, expect } from 'vitest';

import {
  clearVersionMismatches,
  normaliseVersionMismatches,
  recordVersionMismatch,
  type VersionMismatch,
} from '../src/lib/version-mismatch.js';

/**
 * Task 4.3 — the three defences the module states about itself, each of which
 * governs what reaches the popup's DOM rather than what the popup does with it.
 *
 * All three were stated in prose and asserted nowhere: the rebuild, the entry
 * cap and the name cap all survived being deleted with the whole suite green.
 * Every input here is a frame no validator accepted, so this is the boundary.
 */
describe('version-mismatch — what may reach the popup', () => {
  const refusal: VersionMismatch = {
    linkId: 'local',
    linkLabel: 'localhost',
    serverName: 'alltrails-mcp',
    mcpProtocol: 3,
    extensionProtocol: 4,
    at: 1_700_000_000_000,
  };

  describe('normaliseVersionMismatches rebuilds member by member', () => {
    it('drops a field a future version added rather than carrying it to the DOM', () => {
      // The `readEnvelope` / `normalisePendingPair` pattern: the background and
      // the popup read one key, so a shape one of them learns to write must not
      // reach the other's renderer just because storage held it.
      const out = normaliseVersionMismatches({
        'local\u0000alltrails-mcp': {
          ...refusal,
          onClick: 'javascript:alert(1)',
          html: '<img src=x>',
        },
      });
      const rec = out['local\u0000alltrails-mcp'];
      expect(rec).toEqual(refusal);
      expect(Object.keys(rec).sort()).toEqual([
        'at',
        'extensionProtocol',
        'linkId',
        'linkLabel',
        'mcpProtocol',
        'serverName',
      ]);
    });

    it('re-keys from the record, so a stored key that disagrees with it cannot lie', () => {
      // The key is what `clearVersionMismatches` deletes by. A record filed
      // under somebody else's key would be unclearable by the server it names
      // and cleared by one it does not.
      const out = normaliseVersionMismatches({ 'remote:b1\u0000tock-mcp': refusal });
      expect(Object.keys(out)).toEqual(['local\u0000alltrails-mcp']);
      expect(clearVersionMismatches(out, 'local', 'alltrails-mcp')).toEqual({});
    });

    it('refuses a record whose every field is the wrong type', () => {
      expect(
        normaliseVersionMismatches({
          a: { ...refusal, linkId: 42 },
          b: { ...refusal, serverName: '' },
          c: { ...refusal, mcpProtocol: '3' },
          d: { ...refusal, mcpProtocol: 3.5 },
          e: { ...refusal, extensionProtocol: null },
          f: { ...refusal, at: Number.NaN },
          g: null,
          h: 'a refusal',
          i: [refusal],
        }),
      ).toEqual({});
    });

    it('falls back to the link id when the label is not a string, rather than dropping the line', () => {
      // The label is the tooltip; losing it costs diagnosis, losing the whole
      // record costs the refusal itself.
      const out = normaliseVersionMismatches({
        k: { ...refusal, linkLabel: { toString: 'nope' } },
      });
      expect(Object.values(out)[0]?.linkLabel).toBe('local');
    });

    it('answers an empty dict for a stored value that is not an object at all', () => {
      for (const bad of [undefined, null, 'x', 7, [refusal]]) {
        expect(normaliseVersionMismatches(bad)).toEqual({});
      }
    });

    it('caps a name arriving from storage, not only one arriving from a hello', () => {
      const out = normaliseVersionMismatches({
        k: { ...refusal, serverName: 'n'.repeat(200), linkLabel: 'l'.repeat(200) },
      });
      const rec = Object.values(out)[0]!;
      expect(rec.serverName).toHaveLength(64);
      expect(rec.linkLabel).toHaveLength(64);
    });
  });

  it('keeps the newest eight and drops the rest — the popup is not a log', () => {
    let dict: Record<string, VersionMismatch> = {};
    for (let i = 0; i < 9; i++) {
      dict = recordVersionMismatch(dict, {
        ...refusal,
        serverName: `mcp-${i}`,
        at: refusal.at + i * 1000,
      });
    }
    const names = Object.values(dict).map((m) => m.serverName);
    expect(names).toHaveLength(8);
    // The one dropped is the OLDEST, so a popup at the cap shows what just
    // happened rather than what happened first.
    expect(names).not.toContain('mcp-0');
    expect(names).toContain('mcp-8');
  });

  it('caps an attacker-chosen serverName at record time — the popup is 360px wide', () => {
    const dict = recordVersionMismatch({}, { ...refusal, serverName: 'n'.repeat(200) });
    const rec = Object.values(dict)[0]!;
    expect(rec.serverName).toHaveLength(64);
    // And the cap is part of the key, so the capped record is the one a later
    // successful hello from that server clears.
    expect(clearVersionMismatches(dict, 'local', 'n'.repeat(200))).toEqual({});
  });
});
