/**
 * Is `host` an IP-address literal rather than a DNS name (fleet-audit #1247)?
 *
 * A `domains` entry bounds which origins a paired MCP can reach through the
 * user's browser, with that origin's ambient credentials. An IP literal there
 * — `192.168.1.1`, `127.0.0.1`, `169.254.169.254` — points that reach at the
 * user's own LAN or loopback, which no server-side network guard can see. The
 * pair card would show the bare address, but nothing about it says "your
 * router", so the declaration is refused outright, the same way a public
 * suffix is.
 *
 * IPv4 follows the WHATWG URL host parser's "ends in a number" rule: if the
 * last label is all decimal digits, or `0x` + hex, the browser parses the
 * whole host as IPv4 (so `0x7f.0.0.1` and `1.0x7f` are loopback/IPv4 too, and
 * a dotted-decimal regex alone would miss them). No real TLD is numeric, so
 * this never refuses a registrable name. Anything containing `:` (or wrapped
 * in brackets) is an IPv6 literal. Pure and dependency-free — the extension
 * and the server must agree, so both import this one predicate.
 */
export function isIpLiteralHost(host: string): boolean {
  if (host.includes(':') || host.startsWith('[')) return true;
  const labels = host.split('.');
  // A single trailing dot is the FQDN form; the parser ignores it.
  if (labels.length > 1 && labels[labels.length - 1] === '') labels.pop();
  const last = labels[labels.length - 1] ?? '';
  return /^[0-9]+$/.test(last) || /^0x[0-9a-f]*$/i.test(last);
}
