# Changelog

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
