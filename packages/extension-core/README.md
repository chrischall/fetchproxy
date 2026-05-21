# @fetchproxy/extension-core

Browser-side TypeScript shared across extension build targets (Chrome today, Safari/Firefox potentially later).

Workspace-internal. Not published to npm. The Chrome MV3 build lives in [`packages/extension-chrome`](../extension-chrome) and bundles directly from this package's `src/` via esbuild.

Public surface exported from `src/index.ts`:

- URL matching (`isUrlAllowedForDomain`, `isUrlAllowedForAnyDomain`, `isTabUrlMatch`)
- `TrustStore` (chrome.storage.local-backed pair record store, keyed by identity-key hash)
- `SessionKeys` / `SessionEntry` (per-MCP ECDH+HKDF session-key cache)
- `ensureDomainTab` helper (proactively opens a tab on the MCP's declared domains after a successful pair)
- `handleServerHello` (the top-level dispatcher invoked from the background service worker on a server hello)

See the [top-level README](https://github.com/chrischall/fetchproxy#readme) for the architecture and the [protocol reference](https://github.com/chrischall/fetchproxy/blob/main/docs/PROTOCOL.md) for the wire format.
