# Changelog

## [0.5.0](https://github.com/chrischall/fetchproxy/compare/v0.5.0...v0.5.0) (2026-05-25)


### ⚠ BREAKING CHANGES

* **protocol:** capabilities field + read_cookies inner op
* **extension-core:** trust + allowlist over domains[]
* **server:** domains array + per-method domain opt
* **protocol:** multi-domain support in hello frame (0.2.0)
* **extension-core:** popup pair-prompt UI with prefilled code
* **extension-core:** rewrite background for 0.1.0 concentrator + E2E
* **extension-core:** trust store keyed by identity hash, not port
* **server:** FetchproxyServer constructor now requires serverName, version, and domain (previously took only port). The identity dir defaults to ~/.fetchproxy/identity but can be overridden.
* **protocol:** top-level wire is now { hello, ready, frame }. The old ping/pong/request/response are inner frames (inside the encrypted frame's ciphertext) and validated by validateInnerFrame. Hello/ready gain mcpId, crypto identity material, and session-key bootstrap fields.

### Features

* **0.4.0:** JSON-pointer storage extraction + glob patterns in declared keys ([42f7457](https://github.com/chrischall/fetchproxy/commit/42f74574d3ce50689ea43981ddfd4b4426b9aaec))
* **0.4.0:** read_indexed_db capability + bootstrap-helper env-disable, onPairCode, onWaiting ([f4f4d5f](https://github.com/chrischall/fetchproxy/commit/f4f4d5f9d015bcc5e444d40c2d3010a513be4be2))
* **bootstrap:** @fetchproxy/bootstrap one-shot session helper ([76ef7e5](https://github.com/chrischall/fetchproxy/commit/76ef7e546bdf76b8b6156b595c31d008da48d71b))
* **bootstrap:** storageDomain + storageSubdomain selectors for multi-domain MCPs ([1b2011f](https://github.com/chrischall/fetchproxy/commit/1b2011fa88f064ccbe10185b1864fc46255fad90))
* **bootstrap:** storageDomain selector for multi-domain MCPs ([075f281](https://github.com/chrischall/fetchproxy/commit/075f281d9208845ddefe501e30a3bed8502777a4))
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
* **protocol:** 0.1.0 frames + validators — hello/ready/encrypted top-level, inner frames inside ciphertext ([de26331](https://github.com/chrischall/fetchproxy/commit/de26331a95a654f8aecbbad4b021dafbaac34c68))
* **protocol:** capabilities field + read_cookies inner op ([e462b10](https://github.com/chrischall/fetchproxy/commit/e462b10681e53583435d3757d2f34e649dbccf0c))
* **protocol:** derive 6-digit pair code from identity pub (SAS pattern) ([df39f68](https://github.com/chrischall/fetchproxy/commit/df39f681ca6c15f45d85de32d4f1e4e15fbc5e73))
* **protocol:** mcpId generator + parser (server:version:rand) ([1ad5e26](https://github.com/chrischall/fetchproxy/commit/1ad5e26cd624536d711c2eb31151d20984259cc4))
* **protocol:** multi-domain support in hello frame (0.2.0) ([d519c52](https://github.com/chrischall/fetchproxy/commit/d519c526c542651755110e0d0931c93488a432f6))
* **protocol:** new capabilities, scope decls, inner verbs for 0.3.0 ([5aa2b82](https://github.com/chrischall/fetchproxy/commit/5aa2b82c41e99596a51d126993da9139538d3b3b))
* **protocol:** seal/open helpers bridging inner frames and AES-GCM ciphertext ([855e2d9](https://github.com/chrischall/fetchproxy/commit/855e2d907e7db66238de7e01e1bcdbacf8a84105))
* **protocol:** Web Crypto wrappers for X25519, Ed25519, HKDF, AES-GCM ([74dc086](https://github.com/chrischall/fetchproxy/commit/74dc0866664d350729fc8106b3bc4bfe11acbf90))
* **server:** 0.3.0 scope decls + storage / capture-header methods ([1f52a02](https://github.com/chrischall/fetchproxy/commit/1f52a026f7554394db1d08ced08add3edf82af3e))
* **server:** classify FetchResultError into a discriminated kind field ([#24](https://github.com/chrischall/fetchproxy/issues/24)) ([baf1e0a](https://github.com/chrischall/fetchproxy/commit/baf1e0a4117bf8f407d978459c8cddcf462d546f))
* **server:** concentrator host — WS server, peer multiplexer, own-MCP session ([23379fc](https://github.com/chrischall/fetchproxy/commit/23379fc0fd36cc7cc33ecb1be86a08ca05f68499))
* **server:** convenience helpers — request/get/post/getJson/postJson/getHtml ([288392b](https://github.com/chrischall/fetchproxy/commit/288392b72435588da7a94fe3e9b46e252d9d8b98))
* **server:** domains array + per-method domain opt ([25e74e2](https://github.com/chrischall/fetchproxy/commit/25e74e2500b23954af379eae1d87a18a1006ac0d))
* **server:** FetchproxyServer orchestrator — election → host or peer role ([258c626](https://github.com/chrischall/fetchproxy/commit/258c62651b55444e134661ff6f0c2c4ee617e927))
* **server:** guard origin/tabUrl/request-url against the declared domain ([29a45f8](https://github.com/chrischall/fetchproxy/commit/29a45f8338192705c390755f7208c4d3e968e33f))
* **server:** load-or-create persistent identity keypair at ~/.fetchproxy/identity ([0e795e0](https://github.com/chrischall/fetchproxy/commit/0e795e0ecae97539c382e9cff730ff098def9c0c))
* **server:** peer client — dial host, signed hello, encrypted I/O ([f3df5f2](https://github.com/chrischall/fetchproxy/commit/f3df5f24d68dd274e458ef13d5a476c91a8646bb))
* **server:** per-peer session state with monotonic seq + replay rejection ([8618d07](https://github.com/chrischall/fetchproxy/commit/8618d07c634b8042ac00c31b04f3ad62a19bffc6))
* **server:** readCookies() convenience method ([01e469a](https://github.com/chrischall/fetchproxy/commit/01e469a4bbd9fb53ec3a9f504ac5a745bcf69f3d))
* **server:** TCP bind-or-dial election for host vs peer role ([6b6b89a](https://github.com/chrischall/fetchproxy/commit/6b6b89a08bae533644d80d7e2e5942974ee45a4d))


### Bug Fixes

* **ci:** strip stale _authToken from .npmrc so OIDC Trusted Publisher fires ([11471ee](https://github.com/chrischall/fetchproxy/commit/11471eebee9f69955b60081d88e9cdc72141f0c9))
* **ci:** strip stale _authToken so OIDC Trusted Publisher actually fires on Release ([f25687a](https://github.com/chrischall/fetchproxy/commit/f25687aac1226cf69dd0a08dce151dcb277c1908))
* **deps:** bootstrap pins protocol + server to its own version + adds itself to Tag & Bump ([7fad18c](https://github.com/chrischall/fetchproxy/commit/7fad18c130d9d35e72719689fecfea0bb0ef769d))
* **deps:** bootstrap pins protocol + server to same major.minor as itself ([20e5c20](https://github.com/chrischall/fetchproxy/commit/20e5c20b322594177d7f260bc72d8933a110c4db))
* **extension:** chrome.alarms keepalive so MV3 SW doesn't sleep between MCP calls ([188dbf4](https://github.com/chrischall/fetchproxy/commit/188dbf4e2cf1655a88aa5a41eff2edce094e372f))
* **extension:** chrome.alarms keepalive so MV3 SW doesn't sleep between MCP calls ([d1e732e](https://github.com/chrischall/fetchproxy/commit/d1e732efd948a1458b1d562994a2925154e0937c))
* **extension:** storage-read tab match by host-or-subdomain ([1c62a20](https://github.com/chrischall/fetchproxy/commit/1c62a205aa3ace4aef9399d8c7e0b56cb3e6c9e5))
* **extension:** storage-read tab match by host-or-subdomain, not strict prefix ([eef281e](https://github.com/chrischall/fetchproxy/commit/eef281e37fbff1ffb209f880a68166a8219dc4ed))
* MAIN-world capture-logger for CSRF — required for OpenTable ([7b8a01a](https://github.com/chrischall/fetchproxy/commit/7b8a01ad4d0b13aecfa6c9fa7a2de1dbb22d4836))
* **protocol:** validate inner.init.tabUrl + sweep headers for proto pollution ([9f3c747](https://github.com/chrischall/fetchproxy/commit/9f3c7471eb01cfb2683ebfb55fc2c4f372981150))
* **server:** harden host + peer against handshake failures ([c603b47](https://github.com/chrischall/fetchproxy/commit/c603b47854d05d33d12065b143fe90c3c5bf7101))


### Reverts

* roll back "chore(main): release 1.0.0 ([#33](https://github.com/chrischall/fetchproxy/issues/33))" ([#35](https://github.com/chrischall/fetchproxy/issues/35)) ([127031a](https://github.com/chrischall/fetchproxy/commit/127031a09f30d53fbd8cd6d22e8f225547c8bd13))
* roll back "chore(main): release 1.0.0 ([#36](https://github.com/chrischall/fetchproxy/issues/36))" ([#37](https://github.com/chrischall/fetchproxy/issues/37)) ([3e210d6](https://github.com/chrischall/fetchproxy/commit/3e210d646a3640bde8fa8bf5dea2843711188593))


### Refactor

* **extension-core:** trust store keyed by identity hash, not port ([94308f8](https://github.com/chrischall/fetchproxy/commit/94308f88510bb47de9733458011f56b9e0e07cb3))
* **protocol:** export KNOWN_CAPABILITIES + HOSTNAME_RE for reuse ([42937ff](https://github.com/chrischall/fetchproxy/commit/42937ff80cca1e48de8f3d7f11273eacb6257958))
* **protocol:** shared encoding helpers (toB64, fromB64, toHex, concatBytes) ([cb91d36](https://github.com/chrischall/fetchproxy/commit/cb91d36d6ee88f2c16b95acbed4d7f053c26bab6))
* **release:** true lockstep — single-package release-please + cross-dep sync ([#30](https://github.com/chrischall/fetchproxy/issues/30)) ([be99ea1](https://github.com/chrischall/fetchproxy/commit/be99ea17d79ec69e2c277002382fa494e598cbe0))
* **server:** extract buildServerHello helper for host + peer ([9c573fc](https://github.com/chrischall/fetchproxy/commit/9c573fc2dadbf5a31c0663dd7ef96c020817ca03))
* **server:** move subdomain from ctor opt to per-method opt ([2cc06ab](https://github.com/chrischall/fetchproxy/commit/2cc06abc5f34f11383e34b7a207823308ffc01d0))
* **server:** rename origin/tabUrl opt → single subdomain opt ([0a0c34c](https://github.com/chrischall/fetchproxy/commit/0a0c34c1ad88e8e678d6e229ed7be3cefb87750c))
* **server:** split PeerHandle so .ws/.session are explicitly internal ([bb5e3b1](https://github.com/chrischall/fetchproxy/commit/bb5e3b1198ffc2ee2a500ec9daf8a9f714ea90d0))


### Documentation

* add CLAUDE.md ([151fd1d](https://github.com/chrischall/fetchproxy/commit/151fd1d4f0d95ea4d9ce6ef5e8465b92c30b7909))
* add CLAUDE.md — repo conventions, workflows, gotchas ([25ff426](https://github.com/chrischall/fetchproxy/commit/25ff4266cce71973967e963314f8948670698cc3))
* fetchproxy 0.1.0 spec + plan — concentrator + E2E encryption ([f04b8fe](https://github.com/chrischall/fetchproxy/commit/f04b8fe9f4f41dd95ab76e70c25036b212dfce93))
* JSDoc on public exports of @fetchproxy/protocol and @fetchproxy/server ([c79fc84](https://github.com/chrischall/fetchproxy/commit/c79fc8443eb3113ff3819600bf1dc30fe1a64e4a))
* per-package READMEs ([728684d](https://github.com/chrischall/fetchproxy/commit/728684d7968e0e30544abf1e24e71014c4ef0979))
* PROTOCOL.md — capabilities + read_cookies ([1114423](https://github.com/chrischall/fetchproxy/commit/11144234e6afa027f6fd0cafb35fb4bd197e4428))
* PROTOCOL.md update for domains[] ([b227611](https://github.com/chrischall/fetchproxy/commit/b227611978feb1efd4e843c1b151c4129241cb08))
* **protocol:** polish — extension identity key reference ([f3f595f](https://github.com/chrischall/fetchproxy/commit/f3f595f4dd483b934ff242fb43a1ae1ddf06b8dd))
* rewrite PROTOCOL.md for 0.1.x wire format ([a6ec412](https://github.com/chrischall/fetchproxy/commit/a6ec412ee061eaf2dc3341587d494194232d4687))
* security model — threat catalog + defenses ([74268aa](https://github.com/chrischall/fetchproxy/commit/74268aa9b893de0757bdd67f5e203e4e835dc428))
* **security:** overhaul for 0.2.0 — E2E, concentrator, capabilities ([99324be](https://github.com/chrischall/fetchproxy/commit/99324be4a2df57b8cc0b001c9a85b1b978e5e6fb))
* spec + plan for fetchproxy 0.3.0 — session-bootstrap primitives ([40e832e](https://github.com/chrischall/fetchproxy/commit/40e832ebf01719b6bd3bf66cec42a45788e4e11f))
* spec + plan for fetchproxy 0.4.0 ([c987df8](https://github.com/chrischall/fetchproxy/commit/c987df8ee116425787dc30c073c451c6a70f256b))
* spec+plan — open MCP domain tab post-pair if absent ([505111d](https://github.com/chrischall/fetchproxy/commit/505111de1e826272c4abe56e2da5a7783800f8b3))
* **spec:** Transporter — Chrome Web Store launch design ([8393bef](https://github.com/chrischall/fetchproxy/commit/8393befc0043a68d99b6c86c79cb482a39e8a96d))
* **spec:** Transporter — Chrome Web Store launch design ([24eb8bf](https://github.com/chrischall/fetchproxy/commit/24eb8bf64f76e29310bc9fd3a53f0d527b90163e))
* top-level README — overhaul for 0.2.0 ([a430e2e](https://github.com/chrischall/fetchproxy/commit/a430e2e5bbb258e3af81b38a915c4a3986e5dc45))

## [0.5.0](https://github.com/chrischall/fetchproxy/compare/v0.4.3...v0.5.0) (2026-05-25)


### Features

* **server:** classify FetchResultError into a discriminated kind field ([#24](https://github.com/chrischall/fetchproxy/issues/24)) ([baf1e0a](https://github.com/chrischall/fetchproxy/commit/baf1e0a4117bf8f407d978459c8cddcf462d546f))

## [0.4.3](https://github.com/chrischall/fetchproxy/compare/v0.4.2...v0.4.3) (2026-05-24)


### Bug Fixes

* **deps:** bootstrap pins protocol + server to its own version + adds itself to Tag & Bump ([7fad18c](https://github.com/chrischall/fetchproxy/commit/7fad18c130d9d35e72719689fecfea0bb0ef769d))
* **deps:** bootstrap pins protocol + server to same major.minor as itself ([20e5c20](https://github.com/chrischall/fetchproxy/commit/20e5c20b322594177d7f260bc72d8933a110c4db))


### Documentation

* add CLAUDE.md ([151fd1d](https://github.com/chrischall/fetchproxy/commit/151fd1d4f0d95ea4d9ce6ef5e8465b92c30b7909))
* add CLAUDE.md — repo conventions, workflows, gotchas ([25ff426](https://github.com/chrischall/fetchproxy/commit/25ff4266cce71973967e963314f8948670698cc3))
* **spec:** Transporter — Chrome Web Store launch design ([8393bef](https://github.com/chrischall/fetchproxy/commit/8393befc0043a68d99b6c86c79cb482a39e8a96d))
* **spec:** Transporter — Chrome Web Store launch design ([24eb8bf](https://github.com/chrischall/fetchproxy/commit/24eb8bf64f76e29310bc9fd3a53f0d527b90163e))
