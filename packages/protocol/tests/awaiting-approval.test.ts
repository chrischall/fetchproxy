import { describe, it, expect } from 'vitest';
import {
  AWAITING_APPROVAL_REASON_PREFIX,
  parseAwaitingApprovalReason,
  UNSUPPORTED_CAPABILITY_REASON_PREFIX,
} from '../src/index.js';

/**
 * D12 (account-level bridge pairing): the extension queued an approval card on
 * a remote link and nobody is at the browser. It answers the hello with
 * `hello-rejected` whose reason starts `awaiting-approval:`, so the call fails
 * at once with "approve it in your browser" instead of waiting out the
 * session-ready timeout. A documented prefix rather than a field, for the same
 * reason as `unsupported-capability:` — every published validator rebuilds the
 * frame as `{type, mcpId, reason}`.
 */
describe('AWAITING_APPROVAL_REASON_PREFIX', () => {
  it('is the documented wire string', () => {
    expect(AWAITING_APPROVAL_REASON_PREFIX).toBe('awaiting-approval:');
  });

  it('cannot be mistaken for the other documented prefix', () => {
    expect(AWAITING_APPROVAL_REASON_PREFIX.startsWith(UNSUPPORTED_CAPABILITY_REASON_PREFIX)).toBe(false);
    expect(UNSUPPORTED_CAPABILITY_REASON_PREFIX.startsWith(AWAITING_APPROVAL_REASON_PREFIX)).toBe(false);
  });
});

describe('parseAwaitingApprovalReason', () => {
  it('returns the detail after the prefix, trimmed', () => {
    expect(parseAwaitingApprovalReason('awaiting-approval: approve zillow in Chrome')).toBe(
      'approve zillow in Chrome',
    );
  });

  it('parses a bare prefix to an empty detail rather than null', () => {
    expect(parseAwaitingApprovalReason('awaiting-approval:')).toBe('');
    expect(parseAwaitingApprovalReason('awaiting-approval:   ')).toBe('');
  });

  it('does not parse any other reason', () => {
    for (const reason of [
      'unsupported-capability: download (not available in this browser)',
      'sessionSig invalid',
      'serverName/domains mismatch with trust record',
      '',
      // Case, position and punctuation are all part of the contract: a prefix
      // matched loosely would make a non-retryable refusal retryable.
      'Awaiting-approval: approve zillow',
      'AWAITING-APPROVAL: approve zillow',
      ' awaiting-approval: approve zillow',
      'awaiting-approval approve zillow',
      'awaiting approval: approve zillow',
      'not awaiting-approval: approve zillow',
    ]) {
      expect(parseAwaitingApprovalReason(reason), reason).toBeNull();
    }
  });
});
