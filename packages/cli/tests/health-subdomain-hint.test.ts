import { describe, it, expect } from 'vitest';
import { subdomainHintApplies } from '../src/verbs/health.js';

/**
 * `fpx health` adds "your signed-in tab may be on a subdomain — retry with
 * --subdomain www" to a no-tab rejection, because the fetch matcher is
 * strict-prefix and a profile declaring the apex will not match a `www.` tab.
 *
 * Three extension wordings start `no tab matching `, and the hint is right for
 * exactly one of them.
 */
describe('subdomainHintApplies', () => {
  it('applies to a plain no-tab rejection', () => {
    expect(subdomainHintApplies('no tab matching https://creditkarma.com/')).toBe(true);
  });

  it('does not apply while the extension is opening that very tab', () => {
    // #291: the person is told to aim at a subdomain when what they need is to
    // wait a moment for the tab the extension already opened.
    const msg =
      'no tab matching https://www.zillow.com/ answered yet — one is still opening. ' +
      'The extension opened it moments ago and it has not finished loading; ' +
      'retry in a few seconds rather than opening one yourself.';
    expect(subdomainHintApplies(msg)).toBe(false);
  });

  it('does not apply when a tab matched but its content script is unreachable', () => {
    const msg =
      'no tab matching https://x.com/ has the fetchproxy content script loaded ' +
      '(1 URL match, none responded).';
    expect(subdomainHintApplies(msg)).toBe(false);
  });

  it('does not apply to unrelated failures', () => {
    expect(subdomainHintApplies('cookie keys not in declared set: a')).toBe(false);
    expect(subdomainHintApplies('bridge is down')).toBe(false);
  });
});
