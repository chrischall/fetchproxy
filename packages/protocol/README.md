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
| `pair-code` | `pairTranscript` | Deterministic 8-digit SAS code over the pair transcript — both identity pubs, both hello nonces and the MCP's session ephemeral (`SHA256('fetchproxy/4/pair' \| NUL \| …)[0..7]` as a big-endian BigInt `mod 100_000_000`, formatted `XXXX-XXXX`). 3.0.0+; the v3 pair of functions over the two long-term identity pubs alone is gone, so a code cannot be ground offline once and reused against that MCP forever. |
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
