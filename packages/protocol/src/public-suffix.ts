/**
 * Public-suffix awareness for declared `domains` entries.
 *
 * A `domains` entry is matched exact-or-subdomain on every side (the CLI's
 * `isUrlAllowedForAnyDomain`, the server's host gate, the extension's
 * `ensureDomainTab`), so a declaration of `co.uk` or `github.io` claims every
 * site anybody can register under it — the pair prompt shows one plausible
 * string and the user approves the whole registry. `HOSTNAME_RE` already
 * refuses a single-label entry (`com`, `app`), which is why the interesting
 * cases here all have two or more labels.
 *
 * ## WHAT THIS IS — and what it is not
 *
 * This is a HAND-MAINTAINED HEURISTIC, **not** the Mozilla Public Suffix List.
 * The PSL is ~9,900 rules that change every week; vendoring a snapshot of it
 * would read as complete while going stale in place, which is the failure
 * docs/SECURITY.md §"Still-open questions" already rejects for the high-risk
 * keyword heuristic ("Curated lists go stale and give false confidence").
 *
 * It answers `true` on three grounds:
 *
 *  1. **A single label** — every TLD is a public suffix, by definition. No
 *     list needed; this one has no false positives and no gaps.
 *  2. **A generative ccTLD rule** — exactly two labels, a two-ASCII-letter TLD
 *     (ICANN reserves every two-letter TLD for a country), and a second-level
 *     label from `CCTLD_ADMIN_LABELS`, a deliberately short set of
 *     administrative labels (`co`, `com`, `ac`, `gov`, …). That covers most of
 *     the ccTLD second level — `co.uk`, `com.au`, `co.jp`, `com.br`, `gob.mx`,
 *     `ac.nz` — from eleven entries rather than a few hundred.
 *  3. **An explicit list** (`LISTED_PUBLIC_SUFFIXES`) of the multi-label
 *     suffixes rule 2 cannot reach: the Japanese/Korean/Thai administrative
 *     levels, the `.uk` specials, and the vendor ("private") suffixes where
 *     one entry is every customer's site — `github.io`, `vercel.app`,
 *     `herokuapp.com`, `pages.dev`, `s3.amazonaws.com`, and so on.
 *
 * ## What it does NOT cover — stated so nobody reads it as a filter
 *
 *  - **A public suffix absent from this file is ACCEPTED.** This is a speed
 *    bump on the obvious cases, not a gate. The long tail — thousands of
 *    vendor suffixes under `.dev`/`.app`, regional clouds, dynamic-DNS
 *    providers, per-country blog hosts (`blogspot.co.uk` and its ~90
 *    siblings) — is only as complete as the list below, which is to say: not.
 *  - **No wildcard or exception rules.** The PSL's `*.ck` / `!www.ck` and
 *    `*.compute.amazonaws.com` shapes are not modelled; only the literal
 *    entries listed match.
 *  - **Registrable-but-enormous parents are not refused**, because they are
 *    not public suffixes: `amazonaws.com`, `sharepoint.com`, `blogspot.com`'s
 *    owner-level siblings. A declaration of one is still far too wide, and
 *    nothing here says otherwise.
 *  - **Rule 2 is deliberately conservative in the other direction too.**
 *    Labels that are administrative in one country and registrable in another
 *    are kept OUT of `CCTLD_ADMIN_LABELS` — `ad.nl` is a Dutch newspaper,
 *    `ne.ch` and `gr.ch` are Swiss cantons, `web.de` is a mail provider — so
 *    `ne.jp` and friends are listed literally instead. A wrong entry here
 *    refuses a real domain and there is no override, so the trade is
 *    deliberate: this function misses suffixes rather than inventing them.
 *  - **IDN/punycode ccTLDs** (`xn--p1ai`) are not two ASCII letters, so only
 *    the explicit list applies to them; `рф` second levels are not covered.
 *
 * Callers: `validateHello` refuses such an entry outright (`hello.domains`).
 */

/**
 * Second-level labels that are administrative under a two-letter ccTLD
 * essentially everywhere they appear, and are not known to be registrable
 * under any of them. Kept SHORT on purpose — see the note above about a wrong
 * entry refusing a real domain with no way around it.
 */
const CCTLD_ADMIN_LABELS: ReadonlySet<string> = new Set([
  'ac',
  'co',
  'com',
  'edu',
  'gob',
  'gov',
  'mil',
  'net',
  'nom',
  'org',
  'sch',
]);

/**
 * Multi-label public suffixes the generative rule cannot reach. Two groups,
 * kept in one set because the question asked of them is identical.
 */
const LISTED_PUBLIC_SUFFIXES: ReadonlySet<string> = new Set([
  // --- ICANN, under ccTLDs, outside CCTLD_ADMIN_LABELS ---
  'ad.jp',
  'ed.jp',
  'gr.jp',
  'lg.jp',
  'ne.jp',
  'or.jp',
  'go.kr',
  'ne.kr',
  'or.kr',
  'pe.kr',
  're.kr',
  'go.id',
  'my.id',
  'or.id',
  'web.id',
  'go.th',
  'in.th',
  'or.th',
  'me.uk',
  'ltd.uk',
  'plc.uk',
  'nhs.uk',
  'mod.uk',
  'police.uk',
  'parliament.uk',
  'asn.au',
  'id.au',
  'gen.in',
  'ind.in',
  'firm.in',
  'eu.org',

  // --- Vendor ("private") suffixes: one entry = every customer's site ---
  'github.io',
  'githubusercontent.com',
  'gitlab.io',
  'bitbucket.io',
  'pages.dev',
  'workers.dev',
  'r2.dev',
  'trycloudflare.com',
  'vercel.app',
  'now.sh',
  'netlify.app',
  'netlify.live',
  'herokuapp.com',
  'herokussl.com',
  'appspot.com',
  'web.app',
  'firebaseapp.com',
  'cloudfunctions.net',
  'blogspot.com',
  'azurewebsites.net',
  'azurestaticapps.net',
  'azureedge.net',
  'azurecontainer.io',
  'cloudapp.azure.com',
  'trafficmanager.net',
  's3.amazonaws.com',
  'compute.amazonaws.com',
  'compute-1.amazonaws.com',
  'elasticbeanstalk.com',
  'cloudfront.net',
  'awsapprunner.com',
  'amplifyapp.com',
  'fly.dev',
  'onrender.com',
  'railway.app',
  'koyeb.app',
  'deno.dev',
  'replit.dev',
  'repl.co',
  'glitch.me',
  'surge.sh',
  'neocities.org',
  'pythonanywhere.com',
  'readthedocs.io',
  'gitbook.io',
  'myshopify.com',
  'wixsite.com',
  'editorx.io',
  'webflow.io',
  'bubbleapps.io',
  'notion.site',
  'framer.app',
  'framer.website',
  'ngrok.io',
  'ngrok.app',
  'ngrok-free.app',
  'loca.lt',
  'duckdns.org',
  'ddns.net',
  'no-ip.org',
  'dyndns.org',
  'hopto.org',
  'zapto.org',
]);

/**
 * True when `host` looks like a public suffix — a name under which anybody
 * can register, so declaring it as a `domains` entry claims every site beneath
 * it. Heuristic; see the module comment for exactly what it covers and what it
 * does not. Never throws: malformed input answers `false` (the hostname shape
 * check refuses it first).
 */
export function isPublicSuffix(host: string): boolean {
  const normalised = host.trim().toLowerCase().replace(/\.$/, '');
  if (normalised === '') return false;
  const labels = normalised.split('.');
  if (labels.some((l) => l === '')) return false;

  // Rule 1: every TLD is a public suffix.
  if (labels.length === 1) return true;

  // Rule 3 (cheapest exact answer first).
  if (LISTED_PUBLIC_SUFFIXES.has(normalised)) return true;

  // Rule 2: <admin label>.<two-letter ccTLD>.
  if (labels.length === 2) {
    const [secondLevel, tld] = labels;
    if (secondLevel && tld && /^[a-z]{2}$/.test(tld) && CCTLD_ADMIN_LABELS.has(secondLevel)) {
      return true;
    }
  }

  return false;
}
