// @vitest-environment jsdom

import { describe, it, expect, beforeAll } from 'vitest';

// content.ts registers a chrome.runtime.onMessage listener at module load,
// so a minimal `chrome` stub must exist before the (dynamic) import.
let readDomListValues: (selector: {
  itemSelector: string;
  fields: { name: string; selector?: string; attribute?: string }[];
  maxItems?: number;
}) => Record<string, string>[];

beforeAll(async () => {
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { onMessage: { addListener: () => {} } },
  };
  ({ readDomListValues } = await import('../src/content.js'));
});

describe('readDomListValues (isolated-world REPEATED DOM read)', () => {
  it('reads one row per matched item, in document order', () => {
    document.body.innerHTML = `
      <div class="msg"><span class="author">Alice</span><span class="body">hi</span></div>
      <div class="msg"><span class="author">Bob</span><span class="body">hello</span></div>
    `;
    const rows = readDomListValues({
      itemSelector: '.msg',
      fields: [
        { name: 'sender', selector: '.author' },
        { name: 'text', selector: '.body' },
      ],
    });
    expect(rows).toEqual([
      { sender: 'Alice', text: 'hi' },
      { sender: 'Bob', text: 'hello' },
    ]);
  });

  it('returns an empty array when nothing matches itemSelector', () => {
    document.body.innerHTML = `<div>nothing here</div>`;
    const rows = readDomListValues({
      itemSelector: '.msg',
      fields: [{ name: 'text', selector: '.body' }],
    });
    expect(rows).toEqual([]);
  });

  it('omits a field absent on one item but still returns that row', () => {
    document.body.innerHTML = `
      <div class="msg"><span class="author">Alice</span><span class="body">hi</span></div>
      <div class="msg"><span class="author">Bob</span></div>
    `;
    const rows = readDomListValues({
      itemSelector: '.msg',
      fields: [
        { name: 'sender', selector: '.author' },
        { name: 'text', selector: '.body' },
      ],
    });
    expect(rows).toEqual([
      { sender: 'Alice', text: 'hi' },
      { sender: 'Bob' },
    ]);
    expect('text' in rows[1]!).toBe(false);
  });

  it('reads an attribute when declared', () => {
    document.body.innerHTML = `<div class="msg"><time class="ts" datetime="2026-09-21T10:00:00Z">just now</time></div>`;
    const rows = readDomListValues({
      itemSelector: '.msg',
      fields: [{ name: 'time', selector: '.ts', attribute: 'datetime' }],
    });
    expect(rows).toEqual([{ time: '2026-09-21T10:00:00Z' }]);
  });

  it('uses the item element itself when a field has no selector', () => {
    document.body.innerHTML = `<div class="row">first</div><div class="row">second</div>`;
    const rows = readDomListValues({
      itemSelector: '.row',
      fields: [{ name: 'text' }],
    });
    expect(rows).toEqual([{ text: 'first' }, { text: 'second' }]);
  });

  it('truncates to maxItems, in document order', () => {
    document.body.innerHTML = `
      <div class="msg"><span class="body">1</span></div>
      <div class="msg"><span class="body">2</span></div>
      <div class="msg"><span class="body">3</span></div>
    `;
    const rows = readDomListValues({
      itemSelector: '.msg',
      fields: [{ name: 'text', selector: '.body' }],
      maxItems: 2,
    });
    expect(rows).toEqual([{ text: '1' }, { text: '2' }]);
  });

  it('falls back to textContent when the field element has no .value', () => {
    document.body.innerHTML = `<div class="msg"><div class="body">block text</div></div>`;
    const rows = readDomListValues({
      itemSelector: '.msg',
      fields: [{ name: 'text', selector: '.body' }],
    });
    expect(rows).toEqual([{ text: 'block text' }]);
  });

  it('reads <li> items and <button> fields by their text, not .value (B-BUG-2)', () => {
    document.body.innerHTML = `
      <ul>
        <li class="row">first <button class="act">Reply</button></li>
        <li class="row">second <button class="act">Delete</button></li>
      </ul>
    `;
    const rows = readDomListValues({
      itemSelector: '.row',
      fields: [{ name: 'text' }, { name: 'action', selector: '.act' }],
    });
    expect(rows).toEqual([
      { text: 'first Reply', action: 'Reply' },
      { text: 'second Delete', action: 'Delete' },
    ]);
  });
});
