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
        { serverName: 'opentable-mcp', domain: 'opentable.com' },
        { serverName: 'resy-mcp', domain: 'resy.com' },
      ],
    };
    renderPopup(container, state);
    expect(container.textContent).toContain('opentable-mcp');
    expect(container.textContent).toContain('opentable.com');
    expect(container.textContent).toContain('resy-mcp');
    expect(container.textContent).toContain('resy.com');
  });

  it('renders pending-pair with code prominent + cancel default-focused', () => {
    const state: PopupState = {
      mode: 'pending-pair',
      pending: {
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domain: 'opentable.com',
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

  it('calls onApprove when Approve clicked', () => {
    let called = false;
    renderPopup(container, {
      mode: 'pending-pair',
      pending: {
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domain: 'opentable.com',
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
        domain: 'opentable.com',
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
        domain: 'chase.bank',
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
        domain: 'irs.gov',
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
        domain: 'opentable.com',
        pairCode: '111-222',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    });
    expect(container.textContent?.toLowerCase()).not.toContain('high-risk');
  });
});
