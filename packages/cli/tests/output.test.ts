import { describe, it, expect } from 'vitest';
import { EXIT, UsageError, printJson, fetchEnvelope, type Io } from '../src/output.js';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = [];
  const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}

describe('output', () => {
  it('pins the exit-code table', () => {
    expect(EXIT).toEqual({ OK: 0, USAGE: 1, BRIDGE: 2, BOTWALL: 3, HTTP: 4 });
  });

  it('UsageError carries message and hint', () => {
    const e = new UsageError('bad flag', 'try --help');
    expect(e.message).toBe('bad flag');
    expect(e.hint).toBe('try --help');
    expect(e).toBeInstanceOf(Error);
  });

  it('printJson writes 2-space JSON to out only', () => {
    const io = memIo();
    printJson(io, { a: 1 });
    expect(io.outs).toEqual([JSON.stringify({ a: 1 }, null, 2)]);
    expect(io.errs).toEqual([]);
  });

  it('fetchEnvelope wraps status/url/body with no headers field', () => {
    const parsed = JSON.parse(fetchEnvelope({ status: 200, url: 'https://x.com/a', body: 'hi' }));
    expect(parsed).toEqual({ status: 200, url: 'https://x.com/a', body: 'hi' });
  });
});
