# Changelog

## [1.0.0](https://github.com/chrischall/fetchproxy/compare/v0.4.3...v1.0.0) (2026-05-24)


### ⚠ BREAKING CHANGES

* **server:** domains array + per-method domain opt
* **server:** FetchproxyServer constructor now requires serverName, version, and domain (previously took only port). The identity dir defaults to ~/.fetchproxy/identity but can be overridden.

### Features

* **0.4.0:** JSON-pointer storage extraction + glob patterns in declared keys ([42f7457](https://github.com/chrischall/fetchproxy/commit/42f74574d3ce50689ea43981ddfd4b4426b9aaec))
* **0.4.0:** read_indexed_db capability + bootstrap-helper env-disable, onPairCode, onWaiting ([f4f4d5f](https://github.com/chrischall/fetchproxy/commit/f4f4d5f9d015bcc5e444d40c2d3010a513be4be2))
* **bootstrap:** @fetchproxy/bootstrap one-shot session helper ([76ef7e5](https://github.com/chrischall/fetchproxy/commit/76ef7e546bdf76b8b6156b595c31d008da48d71b))
* **protocol+server+extension:** mutual auth — extension identity, joint pair code, ReadyFrame sessionSig ([f9adf12](https://github.com/chrischall/fetchproxy/commit/f9adf12e9fb78ed6d38e5d481da90d25b82fb368))
* **protocol:** new capabilities, scope decls, inner verbs for 0.3.0 ([5aa2b82](https://github.com/chrischall/fetchproxy/commit/5aa2b82c41e99596a51d126993da9139538d3b3b))
* **server:** 0.3.0 scope decls + storage / capture-header methods ([1f52a02](https://github.com/chrischall/fetchproxy/commit/1f52a026f7554394db1d08ced08add3edf82af3e))
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

* MAIN-world capture-logger for CSRF — required for OpenTable ([7b8a01a](https://github.com/chrischall/fetchproxy/commit/7b8a01ad4d0b13aecfa6c9fa7a2de1dbb22d4836))
* **server:** harden host + peer against handshake failures ([c603b47](https://github.com/chrischall/fetchproxy/commit/c603b47854d05d33d12065b143fe90c3c5bf7101))


### Refactor

* **protocol:** export KNOWN_CAPABILITIES + HOSTNAME_RE for reuse ([42937ff](https://github.com/chrischall/fetchproxy/commit/42937ff80cca1e48de8f3d7f11273eacb6257958))
* **protocol:** shared encoding helpers (toB64, fromB64, toHex, concatBytes) ([cb91d36](https://github.com/chrischall/fetchproxy/commit/cb91d36d6ee88f2c16b95acbed4d7f053c26bab6))
* **server:** extract buildServerHello helper for host + peer ([9c573fc](https://github.com/chrischall/fetchproxy/commit/9c573fc2dadbf5a31c0663dd7ef96c020817ca03))
* **server:** move subdomain from ctor opt to per-method opt ([2cc06ab](https://github.com/chrischall/fetchproxy/commit/2cc06abc5f34f11383e34b7a207823308ffc01d0))
* **server:** rename origin/tabUrl opt → single subdomain opt ([0a0c34c](https://github.com/chrischall/fetchproxy/commit/0a0c34c1ad88e8e678d6e229ed7be3cefb87750c))
* **server:** split PeerHandle so .ws/.session are explicitly internal ([bb5e3b1](https://github.com/chrischall/fetchproxy/commit/bb5e3b1198ffc2ee2a500ec9daf8a9f714ea90d0))


### Documentation

* JSDoc on public exports of @fetchproxy/protocol and @fetchproxy/server ([c79fc84](https://github.com/chrischall/fetchproxy/commit/c79fc8443eb3113ff3819600bf1dc30fe1a64e4a))
* per-package READMEs ([728684d](https://github.com/chrischall/fetchproxy/commit/728684d7968e0e30544abf1e24e71014c4ef0979))
