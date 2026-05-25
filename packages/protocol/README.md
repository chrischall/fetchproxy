# @fetchproxy/protocol

> Wire-protocol types, runtime validators, and crypto wrappers for the [fetchproxy](https://github.com/chrischall/fetchproxy) WebSocket protocol.

Internal-ish: most users want [`@fetchproxy/server`](https://www.npmjs.com/package/@fetchproxy/server) instead. `@fetchproxy/server` re-exports the few protocol types MCP authors typically need (`Capability`, `FetchInit`); pull this package in directly only if you're building your own bridge endpoint (alternate server, test harness, custom extension).

See:

- [Top-level README](https://github.com/chrischall/fetchproxy#readme) — what fetchproxy is.
- [`docs/PROTOCOL.md`](https://github.com/chrischall/fetchproxy/blob/main/docs/PROTOCOL.md) — full wire-format reference (frames, handshake, crypto).

## Install

```sh
npm install @fetchproxy/protocol
```

## What's in here

| Module | Exports | Purpose |
|---|---|---|
| `frames` | `PROTOCOL_VERSION`, `Capability`, `KNOWN_CAPABILITIES`, all `…Frame` types, `FetchInit`, `ReadCookiesInit`, `InnerFrame` union, `StoragePointerDecl`, `IndexedDbScopeDecl`, `CaptureHeaderDecl` | Static + runtime descriptions of every frame on the wire. |
| `validate` | `validateFrame`, `validateInnerFrame`, `ProtocolError`, `HOSTNAME_RE` | Defensive JSON validators with no third-party dependencies. Reject prototype-pollution attempts, malformed base64, unknown ops/capabilities, bad hostnames. |
| `crypto` | `RawKeyPair`, `generateX25519`, `generateEd25519`, `ecdhX25519`, `hkdfSha256`, `ed25519Sign`, `ed25519Verify`, `aesGcmSeal`, `aesGcmOpen`, `sha256` | Thin async wrappers around WebCrypto `subtle`. Used by both server and extension. |
| `mcp-id` | `generateMcpId`, `parseMcpId`, `isValidMcpId`, `McpIdParts` | Per-process `<serverName>:<version>:<rand>` ids. |
| `pair-code` | `derivePairCode`, `derivePairCodeFromIds` | Deterministic 6-digit SAS code from X25519 pubkey(s) (`SHA256[0..3] mod 1_000_000`, formatted `XXX-XXX`). |
| `seal` | `sealInnerFrame`, `openEncryptedFrame` | AES-256-GCM encrypt/decrypt of inner JSON payloads keyed by `sessionKey`. |
| `encoding` | `toB64`, `fromB64`, `toHex`, `concatBytes` | Shared base64/hex helpers. |
| `json-pointer` | `evalJsonPointer`, `isValidJsonPointer`, `matchesDeclaredKey`, `undeclaredKeys` | JSON-pointer evaluation + glob matching for storage-pointer extraction. |

## Stability

All exports are part of the published surface and follow semver:

- **Major** bumps signal wire-incompatible changes (new required fields, removed fields, semantic shifts).
- **Minor** bumps add fields or accepted values additively.
- **Patch** bumps are pure fixes.

0.2.0 was a wire-incompatible jump from 0.1.x (singular `domain: string` → `domains: string[]`; added `capabilities`; added `op` discriminator on inner request/response).

## License

MIT.
