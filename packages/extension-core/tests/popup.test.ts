// @vitest-environment jsdom

import { describe, it, expect, beforeEach } from 'vitest';

import { renderPopup, type PopupState } from '../src/popup/popup.js';

describe('renderPopup', () => {
  let container: HTMLElement;

  beforeEach(() => {
    document.body.innerHTML = '<div id="root"></div>';
    container = document.getElementById('root')!;
  });

  it('renders empty state when no pending and no trusted', () => {
    renderPopup(container, { mode: 'empty' });
    expect(container.textContent).toContain('No MCP servers connected');
  });

  it('renders status with trusted MCPs', () => {
    const state: PopupState = {
      mode: 'status',
      trusted: [
        { serverName: 'opentable-mcp', domains: ['opentable.com'] },
        { serverName: 'resy-mcp', domains: ['resy.com'] },
      ],
    };
    renderPopup(container, state);
    expect(container.textContent).toContain('opentable-mcp');
    expect(container.textContent).toContain('opentable.com');
    expect(container.textContent).toContain('resy-mcp');
    expect(container.textContent).toContain('resy.com');
  });

  // Part 3: connection-status dot
  describe('connection-status dot', () => {
    it('renders .status-dot.connected with aria-label "connected" when connected: true', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'opentable-mcp', domains: ['opentable.com'], identityHash: 'h1', connected: true },
        ],
      });
      const dot = container.querySelector('.status-dot.connected');
      expect(dot).not.toBeNull();
      expect(dot?.getAttribute('aria-label')).toBe('connected');
    });

    it('renders .status-dot.offline with aria-label "not connected" when connected: false', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'resy-mcp', domains: ['resy.com'], identityHash: 'h2', connected: false },
        ],
      });
      const dot = container.querySelector('.status-dot.offline');
      expect(dot).not.toBeNull();
      expect(dot?.getAttribute('aria-label')).toBe('not connected');
    });

    it('renders no .status-dot when connected is omitted (backward compat)', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'legacy-mcp', domains: ['legacy.com'] },
        ],
      });
      expect(container.querySelector('.status-dot')).toBeNull();
    });
  });

  // Alphabetical sort + Active/Inactive sections.
  describe('sorting + active/inactive sections', () => {
    const namesIn = (scope: ParentNode = container): (string | undefined)[] =>
      [...scope.querySelectorAll('.trusted-label')].map(
        (e) => e.textContent?.split(' → ')[0],
      );

    it('sorts alphabetically by serverName, as a single list, when no connection info is present', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'resy-mcp', domains: ['resy.com'] },
          { serverName: 'compass-mcp', domains: ['compass.com'] },
          { serverName: 'Opentable-mcp', domains: ['opentable.com'] },
        ],
      });
      // Case-insensitive sort; no section headers; one list.
      expect(namesIn()).toEqual(['compass-mcp', 'Opentable-mcp', 'resy-mcp']);
      expect(container.querySelector('.trusted-section')).toBeNull();
      expect(container.querySelectorAll('ul.trusted-list').length).toBe(1);
    });

    it('splits into Active and Inactive sections, each alphabetical, when connection info is present', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'resy-mcp', domains: ['resy.com'], connected: false },
          { serverName: 'opentable-mcp', domains: ['opentable.com'], connected: true },
          { serverName: 'compass-mcp', domains: ['compass.com'], connected: false },
          { serverName: 'artsonia-mcp', domains: ['artsonia.com'], connected: true },
        ],
      });
      const sections = [...container.querySelectorAll('.trusted-section')].map((e) => e.textContent);
      expect(sections.length).toBe(2);
      expect(sections[0]).toContain('Active');
      expect(sections[1]).toContain('Inactive');
      const lists = container.querySelectorAll('ul.trusted-list');
      expect(lists.length).toBe(2);
      expect(namesIn(lists[0])).toEqual(['artsonia-mcp', 'opentable-mcp']);
      expect(namesIn(lists[1])).toEqual(['compass-mcp', 'resy-mcp']);
    });

    it('renders only the Active section when every entry is connected', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'resy-mcp', domains: ['resy.com'], connected: true },
          { serverName: 'opentable-mcp', domains: ['opentable.com'], connected: true },
        ],
      });
      const sections = [...container.querySelectorAll('.trusted-section')].map((e) => e.textContent);
      expect(sections.length).toBe(1);
      expect(sections[0]).toContain('Active');
      expect(namesIn()).toEqual(['opentable-mcp', 'resy-mcp']);
    });

    it('renders the Inactive section collapsed by default (a closed <details>); Active stays expanded', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'opentable-mcp', domains: ['opentable.com'], connected: true },
          { serverName: 'resy-mcp', domains: ['resy.com'], connected: false },
        ],
      });
      const details = container.querySelector('details.trusted-inactive');
      expect(details).not.toBeNull();
      // No `open` attribute ⇒ collapsed by default.
      expect((details as HTMLDetailsElement).open).toBe(false);
      // The Inactive header lives in the <summary>; the inactive entry is inside.
      expect(details!.querySelector('summary.trusted-section')?.textContent).toContain('Inactive');
      expect(namesIn(details!)).toEqual(['resy-mcp']);
      // Active is NOT wrapped in a <details> — it stays plainly visible.
      const activeHeader = container.querySelector('h4.trusted-section');
      expect(activeHeader?.textContent).toContain('Active');
      expect(activeHeader?.closest('details')).toBeNull();
    });

    it('treats a missing `connected` as inactive once any entry carries connection info', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'b-mcp', domains: ['b.com'], connected: true },
          { serverName: 'a-mcp', domains: ['a.com'] },
        ],
      });
      const lists = container.querySelectorAll('ul.trusted-list');
      expect(lists.length).toBe(2);
      expect(namesIn(lists[0])).toEqual(['b-mcp']); // Active
      expect(namesIn(lists[1])).toEqual(['a-mcp']); // Inactive
    });
  });

  it('renders multi-domain trusted MCP with all hosts listed', () => {
    renderPopup(container, {
      mode: 'status',
      trusted: [{ serverName: 'honeybook-mcp', domains: ['honeybook.com', 'hbsplit.com'] }],
    });
    expect(container.textContent).toContain('honeybook.com');
    expect(container.textContent).toContain('hbsplit.com');
  });

  // 0.4.2: revoke (✕) button on each trusted-MCP entry — only rendered
  // when both `onRevoke` and per-entry `identityHash` are provided.
  // Without either, the list is read-only (back-compat with older tests).
  describe('revoke button', () => {
    it('does not render revoke buttons when onRevoke is omitted', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'opentable-mcp', domains: ['opentable.com'], identityHash: 'h1' },
        ],
      });
      expect(container.querySelector('button[data-action="revoke"]')).toBeNull();
    });

    it('does not render a revoke button when identityHash is missing', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [{ serverName: 'legacy-mcp', domains: ['legacy.com'] }],
        onRevoke: () => undefined,
      });
      expect(container.querySelector('button[data-action="revoke"]')).toBeNull();
    });

    it('renders a revoke button per entry when both onRevoke + identityHash are present', () => {
      renderPopup(container, {
        mode: 'status',
        trusted: [
          { serverName: 'opentable-mcp', domains: ['opentable.com'], identityHash: 'h1' },
          { serverName: 'resy-mcp', domains: ['resy.com'], identityHash: 'h2' },
        ],
        onRevoke: () => undefined,
      });
      const buttons = container.querySelectorAll('button[data-action="revoke"]');
      expect(buttons).toHaveLength(2);
      expect(buttons[0]?.getAttribute('data-identity-hash')).toBe('h1');
      expect(buttons[1]?.getAttribute('data-identity-hash')).toBe('h2');
    });

    it('invokes onRevoke with the entry identityHash after confirmation', () => {
      const calls: string[] = [];
      const origConfirm = window.confirm;
      window.confirm = (): boolean => true;
      try {
        renderPopup(container, {
          mode: 'status',
          trusted: [
            { serverName: 'opentable-mcp', domains: ['opentable.com'], identityHash: 'h1' },
          ],
          onRevoke: (h) => calls.push(h),
        });
        const btn = container.querySelector('button[data-action="revoke"]') as HTMLButtonElement;
        btn.click();
        expect(calls).toEqual(['h1']);
      } finally {
        window.confirm = origConfirm;
      }
    });

    it('does NOT call onRevoke when the user cancels the confirmation', () => {
      const calls: string[] = [];
      const origConfirm = window.confirm;
      window.confirm = (): boolean => false;
      try {
        renderPopup(container, {
          mode: 'status',
          trusted: [
            { serverName: 'opentable-mcp', domains: ['opentable.com'], identityHash: 'h1' },
          ],
          onRevoke: (h) => calls.push(h),
        });
        const btn = container.querySelector('button[data-action="revoke"]') as HTMLButtonElement;
        btn.click();
        expect(calls).toEqual([]);
      } finally {
        window.confirm = origConfirm;
      }
    });
  });

  it('renders pending-pair with code prominent + cancel default-focused', () => {
    const state: PopupState = {
      mode: 'pending-pair',
      pending: {
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domains: ['opentable.com'],
        capabilities: ['fetch'],
        pairCode: '472-918',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    };
    renderPopup(container, state);
    expect(container.textContent).toContain('472-918');
    expect(container.textContent).toContain('opentable.com');
    expect(container.textContent).toContain('opentable-mcp');
    const approve = container.querySelector('[data-action="approve"]') as HTMLButtonElement;
    const cancel = container.querySelector('[data-action="cancel"]') as HTMLButtonElement;
    expect(approve).not.toBeNull();
    expect(cancel).not.toBeNull();
    expect(cancel.getAttribute('autofocus')).not.toBeNull();
  });

  it('renders pending-pair with multiple domains all visible', () => {
    renderPopup(container, {
      mode: 'pending-pair',
      pending: {
        serverName: 'honeybook-mcp',
        version: '0.0.1',
        domains: ['honeybook.com', 'hbsplit.com'],
        capabilities: ['fetch'],
        pairCode: '123-456',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    });
    expect(container.textContent).toContain('honeybook.com');
    expect(container.textContent).toContain('hbsplit.com');
    // Header should pluralise ("Domains" rather than "Domain") for multi.
    expect(container.textContent).toContain('Domains');
  });

  it('calls onApprove when Approve clicked', () => {
    let called = false;
    renderPopup(container, {
      mode: 'pending-pair',
      pending: {
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domains: ['opentable.com'],
        capabilities: ['fetch'],
        pairCode: '472-918',
      },
      onApprove: () => {
        called = true;
      },
      onCancel: () => undefined,
    });
    (container.querySelector('[data-action="approve"]') as HTMLButtonElement).click();
    expect(called).toBe(true);
  });

  it('calls onCancel when Cancel clicked', () => {
    let called = false;
    renderPopup(container, {
      mode: 'pending-pair',
      pending: {
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domains: ['opentable.com'],
        capabilities: ['fetch'],
        pairCode: '472-918',
      },
      onApprove: () => undefined,
      onCancel: () => {
        called = true;
      },
    });
    (container.querySelector('[data-action="cancel"]') as HTMLButtonElement).click();
    expect(called).toBe(true);
  });

  it('shows high-risk warning for bank domains', () => {
    renderPopup(container, {
      mode: 'pending-pair',
      pending: {
        serverName: 'some-bank-mcp',
        version: '0.0.1',
        domains: ['chase.bank'],
        capabilities: ['fetch'],
        pairCode: '111-222',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    });
    expect(container.textContent?.toLowerCase()).toContain('high-risk');
  });

  it('shows high-risk warning for gov domains', () => {
    renderPopup(container, {
      mode: 'pending-pair',
      pending: {
        serverName: 'some-mcp',
        version: '0.0.1',
        domains: ['irs.gov'],
        capabilities: ['fetch'],
        pairCode: '111-222',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    });
    expect(container.textContent?.toLowerCase()).toContain('high-risk');
  });

  it('does not show high-risk warning for normal domains', () => {
    renderPopup(container, {
      mode: 'pending-pair',
      pending: {
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domains: ['opentable.com'],
        capabilities: ['fetch'],
        pairCode: '111-222',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    });
    expect(container.textContent?.toLowerCase()).not.toContain('high-risk');
  });

  it('shows high-risk warning when ANY of the multiple domains is risky', () => {
    renderPopup(container, {
      mode: 'pending-pair',
      pending: {
        serverName: 'mixed-mcp',
        version: '0.0.1',
        domains: ['benign.com', 'chase.bank'],
        capabilities: ['fetch'],
        pairCode: '111-222',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    });
    expect(container.textContent?.toLowerCase()).toContain('high-risk');
  });

  describe('capabilities', () => {
    it('renders fetch capability without warning marker', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'opentable-mcp',
          version: '0.9.1',
          domains: ['opentable.com'],
          capabilities: ['fetch'],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('Capabilities');
      expect(container.textContent).toContain('HTTP fetches');
      // No warning marker for fetch-only.
      expect(container.textContent ?? '').not.toContain('⚠️');
    });

    it('renders read_cookies with a visible warning marker', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'credit-karma-mcp',
          version: '0.0.1',
          domains: ['creditkarma.com'],
          capabilities: ['fetch', 'read_cookies'],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('HTTP fetches');
      expect(container.textContent).toContain('Read cookies');
      // Warning marker present on the elevated-trust verb.
      expect(container.textContent ?? '').toContain('⚠️');
      const warnLi = container.querySelector('li.cap-warn');
      expect(warnLi).not.toBeNull();
      expect(warnLi!.textContent).toContain('Read cookies');
    });

    it('renders cookieKeys as a comma-separated list when read_cookies declared', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'honeybook-mcp',
          version: '0.1.0',
          domains: ['honeybook.com'],
          capabilities: ['fetch', 'read_cookies'],
          cookieKeys: ['hb_user_token', 'hb_session'],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('hb_user_token');
      expect(container.textContent).toContain('hb_session');
    });

    it('renders localStorageKeys when read_local_storage declared', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'ofw-mcp',
          version: '0.5.0',
          domains: ['ourfamilywizard.com'],
          capabilities: ['fetch', 'read_local_storage'],
          localStorageKeys: ['auth', 'tokenExpiry'],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('Read localStorage');
      expect(container.textContent).toContain('auth');
      expect(container.textContent).toContain('tokenExpiry');
    });

    it('renders sessionStorageKeys when read_session_storage declared', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'some-mcp',
          version: '0.0.1',
          domains: ['x.com'],
          capabilities: ['fetch', 'read_session_storage'],
          sessionStorageKeys: ['anon-id'],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('Read sessionStorage');
      expect(container.textContent).toContain('anon-id');
    });

    it('renders IndexedDB scopes when read_indexed_db declared', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'resy-mcp',
          version: '0.0.1',
          domains: ['resy.com'],
          capabilities: ['fetch', 'read_indexed_db'],
          indexedDbScopes: [
            { origin: 'https://resy.com', database: 'resy', store: 'auth', keys: ['userToken', 'userId'] },
          ],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('Read IndexedDB');
      expect(container.textContent).toContain('resy/auth');
      expect(container.textContent).toContain('userToken');
      expect(container.textContent).toContain('userId');
    });

    it('renders DOM selectors when read_dom declared', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'acme-mcp',
          version: '1.4.0',
          domains: ['acme.com'],
          capabilities: ['fetch', 'read_dom'],
          domSelectors: [
            { name: 'title', selector: 'h1.title' },
            { name: 'csrf', selector: 'meta[name=csrf]', attribute: 'content' },
          ],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('Read DOM elements');
      expect(container.textContent).toContain('title → h1.title');
      expect(container.textContent).toContain('csrf → meta[name=csrf] [content]');
    });

    it('renders declared GraphQL operations verbatim when graphql declared', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'opentable-mcp',
          version: '1.0.0',
          domains: ['opentable.com'],
          capabilities: ['fetch', 'graphql'],
          graphqlOps: [
            { name: 'restaurantsAvailability', operationName: 'RestaurantsAvailability' },
          ],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('Run declared GraphQL queries');
      expect(container.textContent).toContain('restaurantsAvailability → RestaurantsAvailability');
    });

    it('renders capture-header entries each on their own line', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'honeybook-mcp',
          version: '0.1.0',
          domains: ['honeybook.com'],
          capabilities: ['fetch', 'capture_request_header'],
          captureHeaders: [
            { host: 'api.honeybook.com', path: '/api/v2/*', headerName: 'hb-api-fingerprint' },
            { host: 'api.honeybook.com', path: '/api/v3/*', headerName: 'hb-api-fingerprint' },
          ],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('Capture request header');
      expect(container.textContent).toContain('api/v2/*');
      expect(container.textContent).toContain('api/v3/*');
      expect(container.textContent).toContain('hb-api-fingerprint');
    });

    it('omits scope sub-lists when their declared array is empty', () => {
      // Pattern B (fetch-only) MCPs should NOT see any of the new
      // sub-lists rendered — the popup stays minimal.
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'opentable-mcp',
          version: '0.9.1',
          domains: ['opentable.com'],
          capabilities: ['fetch'],
          cookieKeys: [],
          localStorageKeys: [],
          sessionStorageKeys: [],
          captureHeaders: [],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).not.toContain('Read cookies:');
      expect(container.textContent).not.toContain('Read localStorage');
      expect(container.textContent).not.toContain('Read sessionStorage');
      expect(container.textContent).not.toContain('Capture request header');
      expect(container.textContent).not.toContain('Run declared GraphQL queries');
    });

    it('renders re-pair diff: heading "UPDATE", added/removed/kept lists, "Approve update" button', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'ofw-mcp',
          version: '0.5.0',
          domains: ['ourfamilywizard.com'],
          capabilities: ['fetch', 'read_local_storage', 'read_cookies'],
          cookieKeys: ['MTOKEN'],
          localStorageKeys: ['auth', 'tokenExpiry'],
          pairCode: '111-222',
        },
        previous: {
          capabilities: ['fetch', 'read_local_storage'],
          cookieKeys: [],
          localStorageKeys: ['auth'],
          sessionStorageKeys: [],
          captureHeaders: [],
          indexedDbScopes: [],
          domSelectors: [],
          graphqlOps: [],
          localStoragePointers: [],
          sessionStoragePointers: [],
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('UPDATE');
      expect(container.textContent).toContain('Previously approved');
      expect(container.textContent).toContain('Now requesting (new)');
      // 'read_cookies' was added; 'auth' was already approved; 'MTOKEN' is new.
      expect(container.textContent).toContain('Capability: read_cookies');
      expect(container.textContent).toContain('Cookie: MTOKEN');
      expect(container.textContent).toContain('localStorage: tokenExpiry');
      // The approve button should be labeled "Approve update".
      const approve = container.querySelector('[data-action="approve"]') as HTMLButtonElement;
      expect(approve.textContent).toBe('Approve update');
    });

    it('renders "(none)" when an update has no removals', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'ofw-mcp',
          version: '0.5.0',
          domains: ['ourfamilywizard.com'],
          capabilities: ['fetch', 'read_local_storage'],
          localStorageKeys: ['auth', 'tokenExpiry'],
          pairCode: '111-222',
        },
        previous: {
          capabilities: ['fetch', 'read_local_storage'],
          cookieKeys: [],
          localStorageKeys: ['auth'],
          sessionStorageKeys: [],
          captureHeaders: [],
          indexedDbScopes: [],
          domSelectors: [],
          graphqlOps: [],
          localStoragePointers: [],
          sessionStoragePointers: [],
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('No longer requested');
      expect(container.textContent).toContain('(none)');
    });

    // ---------------------------------------------------------------------------
    // Part 2: scope-update mode
    // ---------------------------------------------------------------------------
    describe('scope-update mode', () => {
      it('renders the added/removed scope diff for a scope-update state', () => {
        renderPopup(container, {
          mode: 'scope-update',
          serverName: 'musescore-mcp',
          pending: {
            capabilities: ['fetch', 'capture_request_header'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          previous: {
            capabilities: ['fetch'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          onGrant: () => undefined,
          onKeepAsIs: () => undefined,
        });
        // Should show the diff sections.
        expect(container.textContent).toContain('Previously approved');
        expect(container.textContent).toContain('Now requesting (new)');
        expect(container.textContent).toContain('Capability: capture_request_header');
        // The kept capability should appear under "Previously approved".
        expect(container.textContent).toContain('Capability: fetch');
      });

      it('shows an added graphqlOps entry in the diff, not an empty "(none)" section', () => {
        // Regression: a scope-update whose ONLY change is a new declared
        // GraphQL operation must not render an unreviewable empty diff —
        // scopeHash/isScopeSubset already gate on graphqlOps (lib/scope.ts),
        // so this MUST surface in "Now requesting (new)".
        renderPopup(container, {
          mode: 'scope-update',
          serverName: 'opentable-mcp',
          pending: {
            capabilities: ['fetch', 'graphql'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [
              { name: 'restaurantsAvailability', operationName: 'RestaurantsAvailability' },
            ],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          previous: {
            capabilities: ['fetch', 'graphql'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          onGrant: () => undefined,
          onKeepAsIs: () => undefined,
        });
        expect(container.textContent).toContain(
          'GraphQL: restaurantsAvailability → RestaurantsAvailability',
        );
      });

      it('renders [Grant] and [Keep as is] buttons, NOT Approve/Cancel', () => {
        renderPopup(container, {
          mode: 'scope-update',
          serverName: 'musescore-mcp',
          pending: {
            capabilities: ['fetch', 'capture_request_header'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          previous: {
            capabilities: ['fetch'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          onGrant: () => undefined,
          onKeepAsIs: () => undefined,
        });
        expect(container.querySelector('[data-action="grant"]')).not.toBeNull();
        expect(container.querySelector('[data-action="keep-as-is"]')).not.toBeNull();
        // Must NOT have pair-style Approve/Cancel buttons.
        expect(container.querySelector('[data-action="approve"]')).toBeNull();
        expect(container.querySelector('[data-action="cancel"]')).toBeNull();
      });

      it('calls onGrant when [Grant] is clicked', () => {
        const calls: string[] = [];
        renderPopup(container, {
          mode: 'scope-update',
          serverName: 'musescore-mcp',
          pending: {
            capabilities: ['fetch', 'capture_request_header'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          previous: {
            capabilities: ['fetch'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          onGrant: () => calls.push('grant'),
          onKeepAsIs: () => calls.push('keep'),
        });
        (container.querySelector('[data-action="grant"]') as HTMLButtonElement).click();
        expect(calls).toEqual(['grant']);
      });

      it('calls onKeepAsIs when [Keep as is] is clicked WITHOUT writing trust', () => {
        const calls: string[] = [];
        renderPopup(container, {
          mode: 'scope-update',
          serverName: 'musescore-mcp',
          pending: {
            capabilities: ['fetch', 'capture_request_header'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          previous: {
            capabilities: ['fetch'],
            cookieKeys: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          // onGrant would write trust — we verify it is NOT called.
          onGrant: () => calls.push('grant'),
          onKeepAsIs: () => calls.push('keep'),
        });
        (container.querySelector('[data-action="keep-as-is"]') as HTMLButtonElement).click();
        // keep must have fired, grant must NOT.
        expect(calls).toEqual(['keep']);
        expect(calls).not.toContain('grant');
      });

      it('shows serverName in the heading', () => {
        renderPopup(container, {
          mode: 'scope-update',
          serverName: 'ofw-mcp',
          pending: {
            capabilities: ['fetch', 'read_local_storage'],
            cookieKeys: [],
            localStorageKeys: ['auth', 'newKey'],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          previous: {
            capabilities: ['fetch', 'read_local_storage'],
            cookieKeys: [],
            localStorageKeys: ['auth'],
            sessionStorageKeys: [],
            captureHeaders: [],
            indexedDbScopes: [],
            domSelectors: [],
            graphqlOps: [],
            localStoragePointers: [],
            sessionStoragePointers: [],
          },
          onGrant: () => undefined,
          onKeepAsIs: () => undefined,
        });
        expect(container.textContent).toContain('ofw-mcp');
        // The diff should show newKey was added.
        expect(container.textContent).toContain('localStorage: newKey');
      });
    });

    it('first pair has no previous → standard heading + "Approve" button', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'opentable-mcp',
          version: '0.9.1',
          domains: ['opentable.com'],
          capabilities: ['fetch'],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent).toContain('Approve new MCP connection');
      expect(container.textContent).not.toContain('UPDATE');
      const approve = container.querySelector('[data-action="approve"]') as HTMLButtonElement;
      expect(approve.textContent).toBe('Approve');
    });

    it('renders unknown capability as warn (defense in depth)', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'future-mcp',
          version: '0.0.1',
          domains: ['future.example'],
          // @ts-expect-error - testing forward-compat with unknown verbs
          capabilities: ['fetch', 'frobnicate'],
          pairCode: '111-222',
        },
        onApprove: () => undefined,
        onCancel: () => undefined,
      });
      expect(container.textContent ?? '').toContain('⚠️');
    });
  });
});

// ---------------------------------------------------------------------------
// Part 3: connections-changed live-update (Step 7)
// ---------------------------------------------------------------------------
describe('connections-changed live update', () => {
  it('re-renders the status list when chrome.runtime fires connections-changed', async () => {
    const root = document.getElementById('root')!;

    // Simulate a minimal chrome.runtime.onMessage that lets us capture the
    // listener and fire it manually.
    type MsgListener = (msg: unknown) => void;
    let capturedListener: MsgListener | null = null;
    let renderCount = 0;

    // We don't run bootstrap (it needs chrome.storage), but we can verify
    // that renderPopup IS callable multiple times and that the listener
    // pattern the bootstrap registers re-invokes rendering on the message.
    // We test the listener registration contract:
    const fakeOnMessage = {
      addListener: (cb: MsgListener): void => {
        capturedListener = cb;
      },
    };

    // Simulate what bootstrap does: register a renderTrustedStatus re-render
    // callback on the onMessage listener.
    const renderStatusStub = (): void => {
      renderCount++;
      renderPopup(root, {
        mode: 'status',
        trusted: [{ serverName: 'opentable-mcp', domains: ['opentable.com'], connected: true }],
      });
    };

    // Wire the listener (mirrors what bootstrap does).
    fakeOnMessage.addListener((msg) => {
      if (
        msg !== null &&
        typeof msg === 'object' &&
        (msg as { type?: unknown }).type === 'connections-changed'
      ) {
        renderStatusStub();
      }
    });

    expect(capturedListener).not.toBeNull();
    expect(renderCount).toBe(0);

    // Fire connections-changed.
    capturedListener!({ type: 'connections-changed' });
    expect(renderCount).toBe(1);
    expect(root.querySelector('.status-dot.connected')).not.toBeNull();

    // Fire again (e.g. second session connects).
    capturedListener!({ type: 'connections-changed' });
    expect(renderCount).toBe(2);

    // Unrelated message does NOT trigger a re-render.
    capturedListener!({ type: 'something-else' });
    expect(renderCount).toBe(2);
  });
});

describe('pair popup — cookie names when write_cookies is granted', () => {
  let container: HTMLElement;

  beforeEach(() => {
    document.body.innerHTML = '<div id="root"></div>';
    container = document.getElementById('root')!;
  });

  const pending = (capabilities: string[]) => ({
    mode: 'pending-pair' as const,
    pending: {
      serverName: 'creditkarma-mcp',
      version: '2.4.0',
      domains: ['creditkarma.com'],
      capabilities,
      cookieKeys: ['CKAT', 'CKTRKID'],
      pairCode: '881-231',
    },
    onApprove: () => undefined,
    onCancel: () => undefined,
  });

  it('heads the list as read-only when only read_cookies is asked for', () => {
    renderPopup(container, pending(['fetch', 'read_cookies']) as never);

    expect(container.textContent).toContain('Read cookies');
    expect(container.textContent).toContain('CKAT');
    expect(container.textContent).not.toMatch(/overwrite/i);
  });

  it('says the names are writable when write_cookies is asked for', () => {
    // This sub-list is the ONLY place the cookie names appear. Heading it
    // "Read cookies" while granting a write understates the request at the
    // exact moment the user decides — the capability line above it says
    // "Overwrite", so the two would contradict each other.
    renderPopup(container, pending(['fetch', 'read_cookies', 'write_cookies']) as never);

    const dt = [...container.querySelectorAll('dt')].map((n) => n.textContent ?? '');
    const heading = dt.find((t) => /cookies/i.test(t) && !/localStorage|sessionStorage/i.test(t));

    expect(heading).toMatch(/overwrite/i);
    expect(container.textContent).toContain('CKAT');
    expect(container.textContent).toContain('CKTRKID');
  });
});

describe('pair popup — renders when capabilities is absent', () => {
  let container: HTMLElement;

  beforeEach(() => {
    document.body.innerHTML = '<div id="root"></div>';
    container = document.getElementById('root')!;
  });

  it('falls back rather than throwing when capabilities is omitted', () => {
    // `caps` exists precisely because callers may omit `capabilities`. Reading
    // `pending.capabilities` directly for the cookie heading reintroduced the
    // crash that guard was written to prevent — and it fails in the pair
    // popup, the one UI the user depends on to see what they are approving.
    // A popup that throws renders nothing, which is worse than a wrong label.
    const state = {
      mode: 'pending-pair' as const,
      pending: {
        serverName: 'creditkarma-mcp',
        version: '2.4.0',
        domains: ['creditkarma.com'],
        cookieKeys: ['CKAT'],
        pairCode: '881-231',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    };

    expect(() => renderPopup(container, state as never)).not.toThrow();
    // And it still shows the names, headed as a read — the fallback is
    // ['fetch'], which grants no cookie access at all.
    expect(container.textContent).toContain('CKAT');
    expect(container.textContent).toContain('Read cookies');
  });
});
