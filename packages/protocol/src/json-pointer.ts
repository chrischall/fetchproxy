/**
 * 0.4.0+ scope utilities: JSON Pointer evaluation (RFC 6901) for
 * storage extraction, plus glob-aware declared-key matching. Both
 * are tiny helpers with no external dependencies, kept together so
 * the extension + server can import a single module rather than two.
 *
 * Used by storage-read verbs (`read_local_storage` /
 * `read_session_storage`) when the caller declares a JSON-pointer
 * extraction over a stored JSON blob, and by every scope-checking
 * code path that needs glob support in declared key arrays
 * (e.g. `feh--*` matches `feh--12ab`).
 */

/**
 * Evaluate a JSON Pointer against a parsed JSON value.
 *
 * - `pointer === ''` → returns the root.
 * - Tokens may contain `[A-Za-z0-9_\-.]` plus the escapes `~0` and `~1`.
 * - Array indices are decimal integers (>= 0). Anything else returns
 *   `undefined` for arrays.
 * - Crossing through a primitive intermediate (string/number/bool) →
 *   `undefined`.
 */
export function evalJsonPointer(root: unknown, pointer: string): unknown {
  if (pointer === '') return root;
  if (!pointer.startsWith('/')) {
    throw new Error(`invalid JSON pointer (must start with '/'): ${JSON.stringify(pointer)}`);
  }
  const tokens = pointer
    .slice(1)
    .split('/')
    .map((t) => t.replace(/~1/g, '/').replace(/~0/g, '~'));
  let cur: unknown = root;
  for (const tok of tokens) {
    if (cur === null || cur === undefined) return undefined;
    if (Array.isArray(cur)) {
      // Array indices: pure non-negative decimal integers. `'01'`,
      // `'-1'`, `'1.0'`, `''` all fail by RFC 6901.
      if (!/^(0|[1-9]\d*)$/.test(tok)) return undefined;
      const idx = Number(tok);
      if (idx >= cur.length) return undefined;
      cur = cur[idx];
    } else if (typeof cur === 'object') {
      const obj = cur as Record<string, unknown>;
      if (!Object.prototype.hasOwnProperty.call(obj, tok)) return undefined;
      cur = obj[tok];
    } else {
      // Primitive intermediate — pointer can't descend further.
      return undefined;
    }
  }
  return cur;
}

/**
 * 0.4.0+: glob-aware scope-key match. Returns true if `requested`
 * exactly equals a declared literal OR matches a declared glob
 * (`prefix + '*'` matches any `prefix + suffix` where suffix doesn't
 * contain `/` or `;`).
 *
 * Lives here (rather than `validate.ts`) so both extension and
 * server can use it without pulling in the validator's prototype-
 * pollution helpers. Validators still gate the declared list shape
 * upstream via `assertScopeKeyArray` — this function assumes the
 * declared list has already passed validation.
 */
export function matchesDeclaredKey(requested: string, declared: readonly string[]): boolean {
  for (const decl of declared) {
    if (!decl.endsWith('*')) {
      if (decl === requested) return true;
      continue;
    }
    const prefix = decl.slice(0, -1);
    // Glob: requested must start with the literal prefix AND have at
    // least one more character (no `*` matching empty suffix). The
    // suffix is bound to scope-key chars by the declared regex, so we
    // don't need to re-check those here.
    if (requested.length > prefix.length && requested.startsWith(prefix)) {
      return true;
    }
  }
  return false;
}

/**
 * Convenience: returns the subset of `requested` keys that DON'T
 * match any entry in `declared` (after glob expansion). Used by the
 * extension to produce a precise "not in declared set" error.
 */
export function undeclaredKeys(
  requested: readonly string[],
  declared: readonly string[],
): string[] {
  return requested.filter((k) => !matchesDeclaredKey(k, declared));
}

/**
 * Validate a JSON Pointer string. Returns `true` if syntactically
 * valid per RFC 6901 (with the `~0` / `~1` escapes). Does not
 * evaluate; that's `evalJsonPointer`'s job.
 */
export function isValidJsonPointer(pointer: string): boolean {
  if (pointer === '') return true;
  if (!pointer.startsWith('/')) return false;
  // Reject lone `~` not followed by 0 or 1 — the spec allows only
  // `~0` and `~1` as escapes.
  // Scan the string left-to-right looking for unbalanced `~`.
  for (let i = 0; i < pointer.length; i++) {
    if (pointer[i] === '~') {
      const next = pointer[i + 1];
      if (next !== '0' && next !== '1') return false;
      i++; // skip the escape char
    }
  }
  return true;
}
