import type { Profile } from './profiles.js';
import { UsageError } from './output.js';

/**
 * Storage reads (cookies / localStorage / sessionStorage / indexedDb / DOM)
 * target exactly ONE declared domain. With several declared and none picked,
 * the server refuses — but its message names the library option
 * (`pass { domain: '<one of them>' }`), which is not something a CLI user can
 * pass. Refuse here instead, before connecting, naming the flag that fixes it.
 *
 * `fpx pair` does the same check against `--domain`; only the flag differs.
 */
export function requireStorageDomain(profile: Profile, storageDomain: string | undefined): void {
  if (storageDomain !== undefined || profile.domains.length <= 1) return;
  throw new UsageError(
    `profile declares multiple domains (${profile.domains.join(', ')}) — ` +
      'storage reads target one of them: pick it with --storage-domain <domain>',
    'add --storage-subdomain <sub> too if the signed-in tab is on a subdomain.',
  );
}
