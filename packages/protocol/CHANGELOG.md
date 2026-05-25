# Changelog

## [1.0.0](https://github.com/chrischall/fetchproxy/compare/v0.4.2...v1.0.0) (2026-05-25)


### ⚠ BREAKING CHANGES

* **protocol:** capabilities field + read_cookies inner op
* **protocol:** multi-domain support in hello frame (0.2.0)
* **protocol:** top-level wire is now { hello, ready, frame }. The old ping/pong/request/response are inner frames (inside the encrypted frame's ciphertext) and validated by validateInnerFrame. Hello/ready gain mcpId, crypto identity material, and session-key bootstrap fields.

### Features

* **0.4.0:** JSON-pointer storage extraction + glob patterns in declared keys ([42f7457](https://github.com/chrischall/fetchproxy/commit/42f74574d3ce50689ea43981ddfd4b4426b9aaec))
* **0.4.0:** read_indexed_db capability + bootstrap-helper env-disable, onPairCode, onWaiting ([f4f4d5f](https://github.com/chrischall/fetchproxy/commit/f4f4d5f9d015bcc5e444d40c2d3010a513be4be2))
* **protocol+server+extension:** mutual auth — extension identity, joint pair code, ReadyFrame sessionSig ([f9adf12](https://github.com/chrischall/fetchproxy/commit/f9adf12e9fb78ed6d38e5d481da90d25b82fb368))
* **protocol:** 0.1.0 frames + validators — hello/ready/encrypted top-level, inner frames inside ciphertext ([de26331](https://github.com/chrischall/fetchproxy/commit/de26331a95a654f8aecbbad4b021dafbaac34c68))
* **protocol:** capabilities field + read_cookies inner op ([e462b10](https://github.com/chrischall/fetchproxy/commit/e462b10681e53583435d3757d2f34e649dbccf0c))
* **protocol:** derive 6-digit pair code from identity pub (SAS pattern) ([df39f68](https://github.com/chrischall/fetchproxy/commit/df39f681ca6c15f45d85de32d4f1e4e15fbc5e73))
* **protocol:** mcpId generator + parser (server:version:rand) ([1ad5e26](https://github.com/chrischall/fetchproxy/commit/1ad5e26cd624536d711c2eb31151d20984259cc4))
* **protocol:** multi-domain support in hello frame (0.2.0) ([d519c52](https://github.com/chrischall/fetchproxy/commit/d519c526c542651755110e0d0931c93488a432f6))
* **protocol:** new capabilities, scope decls, inner verbs for 0.3.0 ([5aa2b82](https://github.com/chrischall/fetchproxy/commit/5aa2b82c41e99596a51d126993da9139538d3b3b))
* **protocol:** seal/open helpers bridging inner frames and AES-GCM ciphertext ([855e2d9](https://github.com/chrischall/fetchproxy/commit/855e2d907e7db66238de7e01e1bcdbacf8a84105))
* **protocol:** Web Crypto wrappers for X25519, Ed25519, HKDF, AES-GCM ([74dc086](https://github.com/chrischall/fetchproxy/commit/74dc0866664d350729fc8106b3bc4bfe11acbf90))


### Bug Fixes

* MAIN-world capture-logger for CSRF — required for OpenTable ([7b8a01a](https://github.com/chrischall/fetchproxy/commit/7b8a01ad4d0b13aecfa6c9fa7a2de1dbb22d4836))
* **protocol:** validate inner.init.tabUrl + sweep headers for proto pollution ([9f3c747](https://github.com/chrischall/fetchproxy/commit/9f3c7471eb01cfb2683ebfb55fc2c4f372981150))


### Refactor

* **protocol:** export KNOWN_CAPABILITIES + HOSTNAME_RE for reuse ([42937ff](https://github.com/chrischall/fetchproxy/commit/42937ff80cca1e48de8f3d7f11273eacb6257958))
* **protocol:** shared encoding helpers (toB64, fromB64, toHex, concatBytes) ([cb91d36](https://github.com/chrischall/fetchproxy/commit/cb91d36d6ee88f2c16b95acbed4d7f053c26bab6))


### Documentation

* JSDoc on public exports of @fetchproxy/protocol and @fetchproxy/server ([c79fc84](https://github.com/chrischall/fetchproxy/commit/c79fc8443eb3113ff3819600bf1dc30fe1a64e4a))
* per-package READMEs ([728684d](https://github.com/chrischall/fetchproxy/commit/728684d7968e0e30544abf1e24e71014c4ef0979))
