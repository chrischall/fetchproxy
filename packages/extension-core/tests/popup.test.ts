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

  it('renders multi-domain trusted MCP with all hosts listed', () => {
    renderPopup(container, {
      mode: 'status',
      trusted: [{ serverName: 'honeybook-mcp', domains: ['honeybook.com', 'hbsplit.com'] }],
    });
    expect(container.textContent).toContain('honeybook.com');
    expect(container.textContent).toContain('hbsplit.com');
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

    it('renders capture-header entries each on their own line', () => {
      renderPopup(container, {
        mode: 'pending-pair',
        pending: {
          serverName: 'honeybook-mcp',
          version: '0.1.0',
          domains: ['honeybook.com'],
          capabilities: ['fetch', 'capture_request_header'],
          captureHeaders: [
            { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
            { urlPattern: 'https://api.honeybook.com/api/v3/*', headerName: 'hb-api-fingerprint' },
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
