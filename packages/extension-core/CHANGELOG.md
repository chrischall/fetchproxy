# Changelog

## [1.0.0](https://github.com/chrischall/fetchproxy/compare/v0.4.3...v1.0.0) (2026-05-24)


### ⚠ BREAKING CHANGES

* **extension-core:** trust + allowlist over domains[]
* **extension-core:** popup pair-prompt UI with prefilled code
* **extension-core:** rewrite background for 0.1.0 concentrator + E2E
* **extension-core:** trust store keyed by identity hash, not port

### Features

* **0.4.0:** JSON-pointer storage extraction + glob patterns in declared keys ([42f7457](https://github.com/chrischall/fetchproxy/commit/42f74574d3ce50689ea43981ddfd4b4426b9aaec))
* **0.4.0:** read_indexed_db capability + bootstrap-helper env-disable, onPairCode, onWaiting ([f4f4d5f](https://github.com/chrischall/fetchproxy/commit/f4f4d5f9d015bcc5e444d40c2d3010a513be4be2))
* **extension-core:** ensureDomainTab — open MCP domain tab after pairing if absent ([238a2f8](https://github.com/chrischall/fetchproxy/commit/238a2f8f64dd48f2ff8016dbf13bb43f9191827d))
* **extension-core:** handle read_cookies + capability gating + popup display ([1b98206](https://github.com/chrischall/fetchproxy/commit/1b98206d421c0d08bc0e7286e8aee09cceaba1f6))
* **extension-core:** per-mcpId session key cache with replay protection ([cac3e54](https://github.com/chrischall/fetchproxy/commit/cac3e548e0a1a2ddee92da6a9ad00e1352e40e19))
* **extension-core:** popup pair-prompt UI with prefilled code ([054068b](https://github.com/chrischall/fetchproxy/commit/054068b6cd12a49a82499c4d5e15f1f090e7c996))
* **extension-core:** rewrite background for 0.1.0 concentrator + E2E ([89e43b4](https://github.com/chrischall/fetchproxy/commit/89e43b4c9d45562d2be9fda012fede546ba43813))
* **extension-core:** trust + allowlist over domains[] ([ce40b88](https://github.com/chrischall/fetchproxy/commit/ce40b884afa1b85698c76719488f24e8af17e2b6))
* **extension:** pending-pair badge + auto-popup attempt + revoke button ([156e540](https://github.com/chrischall/fetchproxy/commit/156e5400c0ed41a5f2879930ab9ca17eb6c4a30f))
* **extension:** pending-pair badge + auto-popup attempt + revoke trusted MCPs ([d117219](https://github.com/chrischall/fetchproxy/commit/d117219143fda5a2a833788347eb8e19e0d71913))
* **extension:** popup renders capability-diff on re-pair ([cfea95c](https://github.com/chrischall/fetchproxy/commit/cfea95cbfeda250f1541587c2d257ceec397eb05))
* **extension:** trust + popup + content-script + manifest for 0.3.0 ([851c0a5](https://github.com/chrischall/fetchproxy/commit/851c0a5af6b4959f1900affe8b08706305d6aca7))
* **protocol+server+extension:** mutual auth — extension identity, joint pair code, ReadyFrame sessionSig ([f9adf12](https://github.com/chrischall/fetchproxy/commit/f9adf12e9fb78ed6d38e5d481da90d25b82fb368))
* **protocol:** new capabilities, scope decls, inner verbs for 0.3.0 ([5aa2b82](https://github.com/chrischall/fetchproxy/commit/5aa2b82c41e99596a51d126993da9139538d3b3b))


### Bug Fixes

* **extension:** chrome.alarms keepalive so MV3 SW doesn't sleep between MCP calls ([188dbf4](https://github.com/chrischall/fetchproxy/commit/188dbf4e2cf1655a88aa5a41eff2edce094e372f))
* **extension:** chrome.alarms keepalive so MV3 SW doesn't sleep between MCP calls ([d1e732e](https://github.com/chrischall/fetchproxy/commit/d1e732efd948a1458b1d562994a2925154e0937c))
* **extension:** storage-read tab match by host-or-subdomain ([1c62a20](https://github.com/chrischall/fetchproxy/commit/1c62a205aa3ace4aef9399d8c7e0b56cb3e6c9e5))
* **extension:** storage-read tab match by host-or-subdomain, not strict prefix ([eef281e](https://github.com/chrischall/fetchproxy/commit/eef281e37fbff1ffb209f880a68166a8219dc4ed))
* MAIN-world capture-logger for CSRF — required for OpenTable ([7b8a01a](https://github.com/chrischall/fetchproxy/commit/7b8a01ad4d0b13aecfa6c9fa7a2de1dbb22d4836))


### Refactor

* **extension-core:** trust store keyed by identity hash, not port ([94308f8](https://github.com/chrischall/fetchproxy/commit/94308f88510bb47de9733458011f56b9e0e07cb3))
* **protocol:** export KNOWN_CAPABILITIES + HOSTNAME_RE for reuse ([42937ff](https://github.com/chrischall/fetchproxy/commit/42937ff80cca1e48de8f3d7f11273eacb6257958))
* **protocol:** shared encoding helpers (toB64, fromB64, toHex, concatBytes) ([cb91d36](https://github.com/chrischall/fetchproxy/commit/cb91d36d6ee88f2c16b95acbed4d7f053c26bab6))


### Documentation

* per-package READMEs ([728684d](https://github.com/chrischall/fetchproxy/commit/728684d7968e0e30544abf1e24e71014c4ef0979))
