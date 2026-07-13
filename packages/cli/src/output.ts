/** stdout/stderr sinks, injected everywhere so tests capture output. */
export interface Io {
  /** Data channel — response bodies and JSON results ONLY. */
  out(line: string): void;
  /** Everything else: status lines, pair codes, errors, hints. */
  err(line: string): void;
}

export const EXIT = { OK: 0, USAGE: 1, BRIDGE: 2, BOTWALL: 3, HTTP: 4 } as const;

/** Invalid invocation or profile state — maps to EXIT.USAGE. */
export class UsageError extends Error {
  readonly hint?: string;
  constructor(message: string, hint?: string) {
    super(message);
    this.name = 'UsageError';
    this.hint = hint;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function printJson(io: Io, value: unknown): void {
  io.out(JSON.stringify(value, null, 2));
}

/**
 * `--json` envelope for fetch verbs. The bridge returns `{status, url,
 * body}` — response headers never cross the protocol, and `body` is
 * always a UTF-8 string (the extension decodes it).
 */
export function fetchEnvelope(res: { status: number; url: string; body: string }): string {
  return JSON.stringify({ status: res.status, url: res.url, body: res.body }, null, 2);
}
