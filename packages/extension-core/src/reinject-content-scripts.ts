/**
 * Re-inject the manifest's content scripts into already-open tabs after an
 * extension UPDATE.
 *
 * Chrome tears down the content scripts of every open tab when an extension
 * updates, and does not inject the new ones: `content_scripts` in the manifest
 * only applies to navigations from that point on. Every tab the person already
 * had open is therefore left with no listener, and `chrome.tabs.sendMessage`
 * to it fails with "Receiving end does not exist" until they reload it by hand
 * — which nothing tells them to do.
 *
 * That is a bad failure to leave armed, because it fires for EVERY user with a
 * tab open on EVERY release, hits every MCP at once, and looks nothing like an
 * extension problem from the MCP's side. Transporter 2.2.1 -> 2.3.0 did exactly
 * this: two unrelated MCP servers began failing the same evening with no deploy
 * of their own, which read as a shared-library bug and sent the debugging into
 * session-key derivation, then into a revoke/re-pair that discarded a working
 * pairing and changed the state being diagnosed. One reload fixed it.
 *
 * `sendToFirstResponsiveTab` already tolerates an orphaned tab by trying the
 * next match, but that only helps when a SECOND tab on the same origin happens
 * to be open. This closes the case where the only tab is the orphaned one.
 *
 * Deliberately best-effort. Injection legitimately fails on restricted pages
 * (chrome://, the Web Store, PDFs, a tab mid-navigation), and a failure here
 * costs nothing beyond the reload the person would otherwise have done anyway
 * — so every error is swallowed per tab and the sweep continues.
 */

/** Scripts are read from the manifest so this cannot drift from what ships. */
interface ManifestContentScript {
  js?: string[];
  world?: 'MAIN' | 'ISOLATED';
  run_at?: string;
}

declare const chrome: {
  runtime: {
    getManifest: () => { version: string; content_scripts?: ManifestContentScript[] };
  };
  tabs: { query: (q: Record<string, never>) => Promise<{ id?: number; url?: string }[]> };
  scripting?: {
    executeScript: (injection: {
      target: { tabId: number };
      files: string[];
      world?: 'MAIN' | 'ISOLATED';
      injectImmediately?: boolean;
    }) => Promise<unknown>;
  };
};

export interface ReinjectResult {
  /** Tabs that took at least one script. */
  tabs: number;
  /** Tabs where every injection attempt failed (restricted page, gone, …). */
  failed: number;
}

/**
 * True for a URL Chrome will let an extension inject into.
 *
 * Allow-list rather than deny-list: the set of restricted schemes grows with
 * Chrome (`devtools:`, `chrome-untrusted:`, …), and a new one showing up as a
 * log full of failures is worse than a new one being skipped.
 */
export function isInjectableUrl(url: string | undefined): boolean {
  if (!url) return false;
  if (!/^https?:\/\//i.test(url)) return false;
  // The Web Store and Chrome's own hosted pages refuse injection even over
  // https, so they are excluded explicitly rather than discovered by throwing.
  return !/^https:\/\/(chromewebstore\.google\.com|chrome\.google\.com\/webstore)/i.test(url);
}

/** Re-inject every declared content script into every injectable open tab. */
export async function reinjectContentScripts(): Promise<ReinjectResult> {
  // Older Chrome, or a build without the `scripting` permission. Nothing to do
  // and nothing to complain about: the manifest still covers new navigations.
  if (typeof chrome?.scripting?.executeScript !== 'function') return { tabs: 0, failed: 0 };

  const declared = (chrome.runtime.getManifest().content_scripts ?? []).filter(
    (cs): cs is ManifestContentScript & { js: string[] } => Array.isArray(cs.js) && cs.js.length > 0,
  );
  if (declared.length === 0) return { tabs: 0, failed: 0 };

  const tabs = (await chrome.tabs.query({})).filter(
    (t) => typeof t.id === 'number' && isInjectableUrl(t.url),
  );

  let injected = 0;
  let failed = 0;
  for (const tab of tabs) {
    const tabId = tab.id as number;
    let anyLanded = false;
    for (const cs of declared) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId },
          files: cs.js,
          ...(cs.world ? { world: cs.world } : {}),
          // `document_start` scripts exist to beat page JS to a global; on a
          // page that has already loaded there is nothing left to beat, but
          // injecting immediately still matches the declared intent.
          ...(cs.run_at === 'document_start' ? { injectImmediately: true } : {}),
        });
        anyLanded = true;
      } catch {
        // Restricted page, tab closed mid-sweep, or a navigation in flight.
        // Best-effort by design — see the module docblock.
      }
    }
    if (anyLanded) injected++;
    else failed++;
  }
  return { tabs: injected, failed };
}

/**
 * `chrome.runtime.onInstalled` handler.
 *
 * Only `update` orphans content scripts. `install` has no pre-existing tabs
 * worth touching, and `chrome_update` / `shared_module_update` do not tear the
 * extension's scripts down — injecting on those would duplicate live listeners
 * in every open tab for no benefit.
 */
export async function maybeReinjectOnInstalled(details: { reason: string }): Promise<void> {
  if (details.reason !== 'update') return;
  const { tabs, failed } = await reinjectContentScripts();
  console.info(
    `[fetchproxy] extension updated — re-injected content scripts into ${tabs} tab(s)` +
      (failed > 0 ? `, ${failed} could not be injected (restricted pages are normal)` : ''),
  );
}
