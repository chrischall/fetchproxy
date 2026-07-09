# Changelog

## [1.4.0](https://github.com/chrischall/fetchproxy/compare/v1.3.5...v1.4.0) (2026-07-09)


### Features

* **read_dom:** add DOM-value read capability ([#148](https://github.com/chrischall/fetchproxy/issues/148)) ([0ce0949](https://github.com/chrischall/fetchproxy/commit/0ce0949c166b2fdbfea2fdc947b392f73d376d35))

## [1.3.5](https://github.com/chrischall/fetchproxy/compare/v1.3.4...v1.3.5) (2026-07-03)


### Documentation

* mark extension-core as private (not published) in CLAUDE.md ([#137](https://github.com/chrischall/fetchproxy/issues/137)) ([3b88d15](https://github.com/chrischall/fetchproxy/commit/3b88d1517b7666db2b90e31da697af6e131b9144)), closes [#136](https://github.com/chrischall/fetchproxy/issues/136)

## [1.3.4](https://github.com/chrischall/fetchproxy/compare/v1.3.3...v1.3.4) (2026-06-15)


### Documentation

* document Conventional Commit PR-title requirement for release-please ([#133](https://github.com/chrischall/fetchproxy/issues/133)) ([fb4edff](https://github.com/chrischall/fetchproxy/commit/fb4edffb078a14f45192f8891a5a8e6ff0e2bc15))
* refresh CLAUDE.md to current release-please + workflows pipeline ([#135](https://github.com/chrischall/fetchproxy/issues/135)) ([5949757](https://github.com/chrischall/fetchproxy/commit/5949757bf6165794a48aeb734cc408118ea9af14))

## [1.3.3](https://github.com/chrischall/fetchproxy/compare/v1.3.2...v1.3.3) (2026-06-12)


### Documentation

* declare root license, ship LICENSE in package tarballs, add badges ([#126](https://github.com/chrischall/fetchproxy/issues/126)) ([4f87bd8](https://github.com/chrischall/fetchproxy/commit/4f87bd8776c6297ee893f273c1cbf52f1710d07b))

## [1.3.2](https://github.com/chrischall/fetchproxy/compare/v1.3.1...v1.3.2) (2026-06-09)


### Bug Fixes

* **server:** reconnect + per-verb timeout hardening (FP-B1/B2/B3) ([#120](https://github.com/chrischall/fetchproxy/issues/120)) ([de5aec3](https://github.com/chrischall/fetchproxy/commit/de5aec3e7aa7d042c80a903e19b770376e902a32))

## [1.3.1](https://github.com/chrischall/fetchproxy/compare/v1.3.0...v1.3.1) (2026-06-09)


### Bug Fixes

* bound session-ready wait (no bridge-timeout hang) + scroll trusted-MCPs list ([#116](https://github.com/chrischall/fetchproxy/issues/116)) ([6b41b0c](https://github.com/chrischall/fetchproxy/commit/6b41b0cf4f921078153134f209ba698de6853264))
* **server:** address PR [#116](https://github.com/chrischall/fetchproxy/issues/116) review nits (pairCode invariant + pending-map leak) ([#118](https://github.com/chrischall/fetchproxy/issues/118)) ([1d65ccc](https://github.com/chrischall/fetchproxy/commit/1d65cccd0e7a5a51aa08ac25e340867869c1a3ec))

## [1.3.0](https://github.com/chrischall/fetchproxy/compare/v1.2.0...v1.3.0) (2026-06-06)


### Features

* **download:** browser-native download capability (clears Cloudflare via chrome.downloads) ([#113](https://github.com/chrischall/fetchproxy/issues/113)) ([2f465ca](https://github.com/chrischall/fetchproxy/commit/2f465ca00db58f6ba5ec038d378537f22d392ab2))


### Bug Fixes

* **download:** one response frame per request + fast-fail off-domain url (PR [#113](https://github.com/chrischall/fetchproxy/issues/113) nits) ([#115](https://github.com/chrischall/fetchproxy/issues/115)) ([0d22a53](https://github.com/chrischall/fetchproxy/commit/0d22a5338d4f5c1026dd780d968e63562583c8c9))

## [1.2.0](https://github.com/chrischall/fetchproxy/compare/v1.1.0...v1.2.0) (2026-06-04)


### Features

* **extension:** apply granted scope-update to live sessions (no reconnect) ([#110](https://github.com/chrischall/fetchproxy/issues/110)) ([bac59b2](https://github.com/chrischall/fetchproxy/commit/bac59b22d6a108ef1e4734a1b5f92c7ed8bae5b8))


### Refactor

* **extension:** address PR [#110](https://github.com/chrischall/fetchproxy/issues/110) review nits ([#112](https://github.com/chrischall/fetchproxy/issues/112)) ([a0c5ded](https://github.com/chrischall/fetchproxy/commit/a0c5ded0f4d7e650c5ef04cc576a17ee0e8e4577))

## [1.1.0](https://github.com/chrischall/fetchproxy/compare/v1.0.1...v1.1.0) (2026-06-04)


### Features

* add capture_redirect capability ([#108](https://github.com/chrischall/fetchproxy/issues/108)) ([3121dc5](https://github.com/chrischall/fetchproxy/commit/3121dc5411fa4114fc05343adf5dd5319dc4cdde))

## [1.0.1](https://github.com/chrischall/fetchproxy/compare/v1.0.0...v1.0.1) (2026-06-04)


### Bug Fixes

* **extension:** capture listener needs 'extraHeaders' (Cookie header was invisible) ([#106](https://github.com/chrischall/fetchproxy/issues/106)) ([2094255](https://github.com/chrischall/fetchproxy/commit/209425510fc136221a3ed44dcd86a82408f5c039))

## [1.0.0](https://github.com/chrischall/fetchproxy/compare/v0.13.0...v1.0.0) (2026-06-04)


### ⚠ BREAKING CHANGES

* **protocol:** captureHeaders as {host, path?, headerName} validated against domains ([#104](https://github.com/chrischall/fetchproxy/issues/104))

### Features

* **protocol:** captureHeaders as {host, path?, headerName} validated against domains ([#104](https://github.com/chrischall/fetchproxy/issues/104)) ([e8407e6](https://github.com/chrischall/fetchproxy/commit/e8407e69f8256fdf190d8903ea1d02dea95121a6))
* **server:** validate declared captureHeaders at construction ([#102](https://github.com/chrischall/fetchproxy/issues/102)) ([00b2cc1](https://github.com/chrischall/fetchproxy/commit/00b2cc1abd76c9ad5b518e3690b38267f437a6a9))

## [0.13.0](https://github.com/chrischall/fetchproxy/compare/v0.12.0...v0.13.0) (2026-06-03)


### Features

* **server:** peer re-elects to host when its host dies ([#100](https://github.com/chrischall/fetchproxy/issues/100)) ([4bd94fe](https://github.com/chrischall/fetchproxy/commit/4bd94fe5312eb5ee226750d3e4ef28aef42a591a))

## [0.12.0](https://github.com/chrischall/fetchproxy/compare/v0.11.1...v0.12.0) (2026-06-03)


### Features

* **extension:** per-identity pairing + non-blocking scope growth + connection dot ([#97](https://github.com/chrischall/fetchproxy/issues/97)) ([daf4046](https://github.com/chrischall/fetchproxy/commit/daf40468e69cc7fe839d6a58095e83be11691200))


### Bug Fixes

* **extension:** address [#97](https://github.com/chrischall/fetchproxy/issues/97) review nits (supersede-on-collision + dead code) ([#99](https://github.com/chrischall/fetchproxy/issues/99)) ([1a98d25](https://github.com/chrischall/fetchproxy/commit/1a98d2558c32f2e932ea08009d92802093a9863e))

## [0.11.1](https://github.com/chrischall/fetchproxy/compare/v0.11.0...v0.11.1) (2026-05-30)


### Bug Fixes

* **server:** drop px-sensor marker that false-flagged every SSR page ([#95](https://github.com/chrischall/fetchproxy/issues/95)) ([54de894](https://github.com/chrischall/fetchproxy/commit/54de8941ebd61676e5277cbef8ddfee2435eec09))

## [0.11.0](https://github.com/chrischall/fetchproxy/compare/v0.10.0...v0.11.0) (2026-05-29)


### Features

* **server:** shared SSR-parsing + batch-paging helpers ([#94](https://github.com/chrischall/fetchproxy/issues/94)) ([ee4ed05](https://github.com/chrischall/fetchproxy/commit/ee4ed05ce8c9941722af98f477ff69f0e6f89479))


### Bug Fixes

* **ci:** treat instant-merge race as success in auto-merge arm ([#93](https://github.com/chrischall/fetchproxy/issues/93)) ([4354fb2](https://github.com/chrischall/fetchproxy/commit/4354fb2eb27cd9ba0ddf3c00c05515ec3eb43535))
* **server:** win the SW-eviction cold-start race ([#90](https://github.com/chrischall/fetchproxy/issues/90)) ([#91](https://github.com/chrischall/fetchproxy/issues/91)) ([50e12cc](https://github.com/chrischall/fetchproxy/commit/50e12ccdaab0ad13689a76771eb9175bf6e32b40))

## [0.10.0](https://github.com/chrischall/fetchproxy/compare/v0.9.0...v0.10.0) (2026-05-28)


### Features

* **server:** add requestJson + runProbe consumer helpers ([#88](https://github.com/chrischall/fetchproxy/issues/88)) ([#89](https://github.com/chrischall/fetchproxy/issues/89)) ([1b01588](https://github.com/chrischall/fetchproxy/commit/1b01588dcd7f265ef309af14b63fc2e4ed12a160))
* **server:** expose resolved fetchTimeoutMs + bridgeReviveDelayMs via bridgeHealth() ([#83](https://github.com/chrischall/fetchproxy/issues/83)) ([bace261](https://github.com/chrischall/fetchproxy/commit/bace26125e9a52cfd18f6bf051032f95dbb20bf9))
* **server:** transport resilience kit — bot-wall classification + throttle + backoff + deadline ([#87](https://github.com/chrischall/fetchproxy/issues/87)) ([8ead6bd](https://github.com/chrischall/fetchproxy/commit/8ead6bdea532f4ab8b9aa61bc97369e7ee0f7b57))

## [0.9.0](https://github.com/chrischall/fetchproxy/compare/v0.8.0...v0.9.0) (2026-05-28)


### Features

* **ci:** add pre-release dist-tag (next) flow for cohort migrations ([#79](https://github.com/chrischall/fetchproxy/issues/79)) ([edd2e54](https://github.com/chrischall/fetchproxy/commit/edd2e54d0e006349e8f9cce5419f596b436aad56))
* **server:** flip keepAliveIntervalMs default to 25_000 + bridgeHealth().keepAlive observability surface ([#77](https://github.com/chrischall/fetchproxy/issues/77)) ([62faa38](https://github.com/chrischall/fetchproxy/commit/62faa38b8ce0f118c450862ecfad73b0de7444c0))
* **server:** hoist bulk-fan-out helpers (mapWithConcurrency, retryOnceOnTimeout, classifyRowError) ([#69](https://github.com/chrischall/fetchproxy/issues/69)) ([80c78c0](https://github.com/chrischall/fetchproxy/commit/80c78c00ac801f70aebd8a6bd986b6f3b64c95a8))
* **server:** proactive keep-alive ping (closes [#67](https://github.com/chrischall/fetchproxy/issues/67)) ([#68](https://github.com/chrischall/fetchproxy/issues/68)) ([6d46b47](https://github.com/chrischall/fetchproxy/commit/6d46b476c74b3bc4845be833d909ce2a27f92f5a))


### Documentation

* **server:** JSDoc audit + Server options README section ([#80](https://github.com/chrischall/fetchproxy/issues/80)) ([89490e1](https://github.com/chrischall/fetchproxy/commit/89490e1e2ca63f2621ffb4054539801f59707be2))
* **server:** refresh keepAlive JSDoc + bridgeHealth wording per [#77](https://github.com/chrischall/fetchproxy/issues/77) review nits ([#81](https://github.com/chrischall/fetchproxy/issues/81)) ([520a272](https://github.com/chrischall/fetchproxy/commit/520a272a71e4f5eaa21330f4cb4241aba37e48bb))

## [0.8.0](https://github.com/chrischall/fetchproxy/compare/v0.7.1...v0.8.0) (2026-05-27)


### Features

* **server,bootstrap:** 0.8.0 cohort follow-ups — typed-error diagnostics, bridgeHealth expansion, tabUrl auto-derive, bootstrap pass-through, classifyBridgeError ([#63](https://github.com/chrischall/fetchproxy/issues/63)) ([415f84d](https://github.com/chrischall/fetchproxy/commit/415f84dad4e76957c484e38152e5020cf7a3c680))
* **server:** 0.8.0 polish — on-by-default + bridgeHealth() + capture-by-declaration ([#61](https://github.com/chrischall/fetchproxy/issues/61)) ([62b8a0e](https://github.com/chrischall/fetchproxy/commit/62b8a0e5dcd48ae280011929cdd4cc3de1b00e60))
* **server:** fetchTimeoutMs + bridgeReviveDelayMs + typed errors ([#58](https://github.com/chrischall/fetchproxy/issues/58)) ([ba307d7](https://github.com/chrischall/fetchproxy/commit/ba307d7b03f9f77566bd22987e49b5116542ef89))


### Bug Fixes

* **server:** address PR [#58](https://github.com/chrischall/fetchproxy/issues/58) review nits — explicit retryAttempted + url on capture errors ([#60](https://github.com/chrischall/fetchproxy/issues/60)) ([d4e47da](https://github.com/chrischall/fetchproxy/commit/d4e47da05e86600ccddafc2394137e6b752730e5))
* **server:** thread retryAttempted on the result envelope (PR [#60](https://github.com/chrischall/fetchproxy/issues/60) race) ([#62](https://github.com/chrischall/fetchproxy/issues/62)) ([13bcb0d](https://github.com/chrischall/fetchproxy/commit/13bcb0d76fe96ca494e052dd0b221d78c892311f))
* **tests:** de-flake elapsedMs assertion on fast CI runners ([#64](https://github.com/chrischall/fetchproxy/issues/64)) ([fc746af](https://github.com/chrischall/fetchproxy/commit/fc746af56034748c7eab742091bbb4450aae9704))

## [0.7.1](https://github.com/chrischall/fetchproxy/compare/v0.7.0...v0.7.1) (2026-05-26)


### Bug Fixes

* **ci,extension:** auto-review warn arms merge + open tabs for all domains ([#56](https://github.com/chrischall/fetchproxy/issues/56)) ([0c6d65b](https://github.com/chrischall/fetchproxy/commit/0c6d65b35b70ef5b7c37d9ead7da5ca82047b31c))
* **server:** model-directive pair-code error message ([#54](https://github.com/chrischall/fetchproxy/issues/54)) ([3b199b9](https://github.com/chrischall/fetchproxy/commit/3b199b9b03f9e147c8971f2ff86a7e41c8e84886))

## [0.7.0](https://github.com/chrischall/fetchproxy/compare/v0.6.0...v0.7.0) (2026-05-26)


### Features

* **extension:** Transporter — Chrome Web Store launch prep ([#52](https://github.com/chrischall/fetchproxy/issues/52)) ([f5b3165](https://github.com/chrischall/fetchproxy/commit/f5b316563daa404c1c65607479528b16c291d6bc))

## [0.6.0](https://github.com/chrischall/fetchproxy/compare/v0.5.1...v0.6.0) (2026-05-26)


### Features

* **server:** lazy bridge connect — listen() loads identity only ([#51](https://github.com/chrischall/fetchproxy/issues/51)) ([8309c2b](https://github.com/chrischall/fetchproxy/commit/8309c2b727f41f7bcc0cef6c464b09005754b557))


### Bug Fixes

* 3 MCPs can work concurrently (peer session renegotiation + pendingPair dict) ([#49](https://github.com/chrischall/fetchproxy/issues/49)) ([4272e98](https://github.com/chrischall/fetchproxy/commit/4272e980404055721f35b0c2cd339871b00dc3df))
* **ci:** prevent labeled event from cancelling auto-review ([#47](https://github.com/chrischall/fetchproxy/issues/47)) ([40bc4db](https://github.com/chrischall/fetchproxy/commit/40bc4dbcbf9b6036d28b5247777fc4d4ccb0dc14))
* **extension:** handlers iterate ALL matching tabs instead of just the first ([#50](https://github.com/chrischall/fetchproxy/issues/50)) ([8bd437b](https://github.com/chrischall/fetchproxy/commit/8bd437bc59d8ebf1a28aa33987baef5e6634d1fc))

## [0.5.1](https://github.com/chrischall/fetchproxy/compare/v0.5.0...v0.5.1) (2026-05-25)


### Bug Fixes

* session-key renegotiation on extension reconnect + cleanup ([#44](https://github.com/chrischall/fetchproxy/issues/44)) ([cd612da](https://github.com/chrischall/fetchproxy/commit/cd612daabc061910d83acae940d2686598bea9aa))

## [0.5.0](https://github.com/chrischall/fetchproxy/compare/v0.4.4...v0.5.0) (2026-05-25)


### Features

* **server:** classify `FetchResultError` into a discriminated `kind` field — `'content_script_unreachable' | 'no_tab' | 'tab_fetch_failed' | 'domain_denied' | 'capability_denied' | 'body_too_large' | 'other'`. Downstream MCPs can now branch on `result.kind` instead of pattern-matching the `error` string; `classifyFetchError` is also exported for use outside `FetchproxyServer`. ([#24](https://github.com/chrischall/fetchproxy/pull/24))


### CI / Release

* Lockstep versioning across all five sub-packages — release-please now treats fetchproxy as a single-package release with `extra-files` syncing every sub-package's `version` field, plus a workflow step that bumps inter-package `^X.Y.Z` deps in the release PR ([#30](https://github.com/chrischall/fetchproxy/pull/30), [#32](https://github.com/chrischall/fetchproxy/pull/32))
* Fixed OIDC publish pipeline — `.npmrc` strip now matches the sibling-MCP pattern (only `always-auth`, keep `_authToken`), and the publish job gates on the canonical `release_created == 'true'` output ([#40](https://github.com/chrischall/fetchproxy/pull/40))
* Per-workspace VERSION reads in the publish job ([#29](https://github.com/chrischall/fetchproxy/pull/29))
* Deferred `fromJSON` resolution to run-time so post-merge no-PR runs don't crash ([#34](https://github.com/chrischall/fetchproxy/pull/34))


### Note

Two earlier v1.0.0 release attempts (#36, #38) were rolled back (#35, #37, #40) and v1.0.0 tag/release deleted — the major-bump signal from release-please was driven by `BREAKING CHANGE:` footers from the 0.0.x → 0.4.x development era that had already shipped in prior 0.x releases. 0.5.0 is the actual delta from 0.4.4.

## [0.4.3](https://github.com/chrischall/fetchproxy/compare/v0.4.2...v0.4.3) (2026-05-24)


### Bug Fixes

* **deps:** bootstrap pins protocol + server to its own version + adds itself to Tag & Bump ([7fad18c](https://github.com/chrischall/fetchproxy/commit/7fad18c130d9d35e72719689fecfea0bb0ef769d))
* **deps:** bootstrap pins protocol + server to same major.minor as itself ([20e5c20](https://github.com/chrischall/fetchproxy/commit/20e5c20b322594177d7f260bc72d8933a110c4db))


### Documentation

* add CLAUDE.md ([151fd1d](https://github.com/chrischall/fetchproxy/commit/151fd1d4f0d95ea4d9ce6ef5e8465b92c30b7909))
* add CLAUDE.md — repo conventions, workflows, gotchas ([25ff426](https://github.com/chrischall/fetchproxy/commit/25ff4266cce71973967e963314f8948670698cc3))
* **spec:** Transporter — Chrome Web Store launch design ([8393bef](https://github.com/chrischall/fetchproxy/commit/8393befc0043a68d99b6c86c79cb482a39e8a96d))
* **spec:** Transporter — Chrome Web Store launch design ([24eb8bf](https://github.com/chrischall/fetchproxy/commit/24eb8bf64f76e29310bc9fd3a53f0d527b90163e))
