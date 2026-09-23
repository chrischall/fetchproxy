import { describe, it, expect } from 'vitest';
import { bootstrap, type BootstrapServerFactory } from '../src/index.js';

// B-BUG-14: declared keys may be trailing-* globs at the server level, but a
// lift passed them to the extension as LITERAL names (chrome.cookies.get with
// name 'feh--*'), which match nothing — so a glob always came back empty and
// was reported as "missing" under the pattern's own name, with no hint that
// globs are unsupported in a lift. Refuse them up front instead.

function countingFactory(): { factory: BootstrapServerFactory; made: () => number } {
  let made = 0;
  const factory: BootstrapServerFactory = () => {
    made++;
    return {
      listen: async () => undefined,
      close: async () => undefined,
      readCookies: async () => '',
      readLocalStorage: async () => ({}),
      readSessionStorage: async () => ({}),
      captureRequestHeader: async () => '',
      readIndexedDb: async () => ({}),
    };
  };
  return { factory, made: () => made };
}

const base = {
  serverName: 'glob-mcp',
  version: '0.0.1',
  domains: ['example.com'],
};

describe('B-BUG-14: glob keys in a lift', () => {
  for (const bucket of ['cookies', 'localStorage', 'sessionStorage'] as const) {
    it(`rejects a glob in declare.${bucket} before opening the bridge`, async () => {
      const { factory, made } = countingFactory();
      const declare = { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] } as {
        cookies: string[];
        localStorage: string[];
        sessionStorage: string[];
        captureHeaders: [];
      };
      declare[bucket] = ['sid', 'feh--*'];
      await expect(bootstrap({ ...base, declare, _serverFactory: factory })).rejects.toThrow(
        new RegExp(`declare\\.${bucket}.*"feh--\\*".*glob`),
      );
      expect(made()).toBe(0);
    });
  }

  it('still accepts literal keys', async () => {
    const { factory } = countingFactory();
    await expect(
      bootstrap({
        ...base,
        declare: { cookies: ['sid'], localStorage: [], sessionStorage: [], captureHeaders: [] },
        _serverFactory: factory,
      }),
    ).resolves.toBeDefined();
  });
});
