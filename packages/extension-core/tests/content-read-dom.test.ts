// @vitest-environment jsdom

import { describe, it, expect, beforeAll } from 'vitest';

// content.ts registers a chrome.runtime.onMessage listener at module load,
// so a minimal `chrome` stub must exist before the (dynamic) import.
let readDomValues: (
  selectors: { name: string; selector: string; attribute?: string }[],
) => Record<string, string>;

beforeAll(async () => {
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { onMessage: { addListener: () => {} } },
  };
  ({ readDomValues } = await import('../src/content.js'));
});

describe('readDomValues (isolated-world DOM read)', () => {
  it('reads textContent, form value, and attribute; coerces to string', () => {
    document.body.innerHTML = `
      <h1 class="title">Hello World</h1>
      <input id="tok" value="abc123" />
      <a id="lnk" href="https://example.com/x">link</a>
    `;
    const values = readDomValues([
      { name: 'title', selector: 'h1.title' },
      { name: 'token', selector: '#tok' },
      { name: 'href', selector: '#lnk', attribute: 'href' },
    ]);
    expect(values).toEqual({
      title: 'Hello World',
      token: 'abc123',
      href: 'https://example.com/x',
    });
  });

  it('omits a name whose element is missing', () => {
    document.body.innerHTML = `<h1 class="title">Present</h1>`;
    const values = readDomValues([
      { name: 'title', selector: 'h1.title' },
      { name: 'missing', selector: '#nope' },
    ]);
    expect(values).toEqual({ title: 'Present' });
    expect('missing' in values).toBe(false);
  });

  it('omits a name whose requested attribute is absent', () => {
    document.body.innerHTML = `<a id="lnk">no href</a>`;
    const values = readDomValues([{ name: 'href', selector: '#lnk', attribute: 'href' }]);
    expect(values).toEqual({});
    expect('href' in values).toBe(false);
  });

  it('falls back to textContent when the element has no .value', () => {
    document.body.innerHTML = `<div id="d">block text</div>`;
    const values = readDomValues([{ name: 'd', selector: '#d' }]);
    expect(values).toEqual({ d: 'block text' });
  });
});
