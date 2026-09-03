# Changelog

## [2.5.1](https://github.com/chrischall/fetchproxy/compare/v2.5.0...v2.5.1) (2026-09-03)


### Bug Fixes

* **extension:** relay writes through a tab that can inject x-csrf-token ([#287](https://github.com/chrischall/fetchproxy/issues/287)) ([bc471a2](https://github.com/chrischall/fetchproxy/commit/bc471a2b8890ec2ae84d67525c8f131a468e0114))

## [2.5.0](https://github.com/chrischall/fetchproxy/compare/v2.4.2...v2.5.0) (2026-09-02)


### Features

* **server:** expose the extension link state in bridge health and the probe ([#282](https://github.com/chrischall/fetchproxy/issues/282)) ([0e33fc8](https://github.com/chrischall/fetchproxy/commit/0e33fc8c2e705a566fe1a6dd58c3ab6b80e0dc48))


### Bug Fixes

* **server:** forget an unapproved pair code when the extension goes away ([#285](https://github.com/chrischall/fetchproxy/issues/285)) ([76a404e](https://github.com/chrischall/fetchproxy/commit/76a404e46577d94c971518fcc684e2a866bd48f8))

## [2.4.2](https://github.com/chrischall/fetchproxy/compare/v2.4.1...v2.4.2) (2026-09-02)


### Bug Fixes

* **server:** explain the deadline cap on download() too, and test all three ([#281](https://github.com/chrischall/fetchproxy/issues/281)) ([971a50c](https://github.com/chrischall/fetchproxy/commit/971a50cafdecacd182352371b8e96bcbfb7b28e8))
* **server:** say when fetchTimeoutMs is what capped a per-call timeout ([#278](https://github.com/chrischall/fetchproxy/issues/278)) ([885a12f](https://github.com/chrischall/fetchproxy/commit/885a12f10764ff68d3e5bb8b25c3b2d92a22a6ff))

## [2.4.1](https://github.com/chrischall/fetchproxy/compare/v2.4.0...v2.4.1) (2026-09-02)


### Bug Fixes

* **extension:** tag MAIN-world failures so the world is readable off the error ([#274](https://github.com/chrischall/fetchproxy/issues/274)) ([989c383](https://github.com/chrischall/fetchproxy/commit/989c38316aad4f4935afa1a9f897f4d1bbbfb21a))
* **server:** keep in-page fetch failures classified as tab_fetch_failed ([#276](https://github.com/chrischall/fetchproxy/issues/276)) ([d8e74fd](https://github.com/chrischall/fetchproxy/commit/d8e74fd7dd0ec1fe0db9ab806b84d20d3f301d6c))


### Documentation

* how to reach an API through the bridge, keyed by the error you get ([#269](https://github.com/chrischall/fetchproxy/issues/269)) ([c26d5e9](https://github.com/chrischall/fetchproxy/commit/c26d5e9eea178660dfb29d47cfd4e6c537637dcf))
* say four failures in the intro, matching the worked example ([#272](https://github.com/chrischall/fetchproxy/issues/272)) ([4392807](https://github.com/chrischall/fetchproxy/commit/439280726645a93105a3043459e8703f0440bb19))

## [2.4.0](https://github.com/chrischall/fetchproxy/compare/v2.3.2...v2.4.0) (2026-09-02)


### Features

* **extension:** add fetch_in_page for requests the isolated world can't make ([#267](https://github.com/chrischall/fetchproxy/issues/267)) ([2436aec](https://github.com/chrischall/fetchproxy/commit/2436aec638e37fb86b71ae6f28ecf86f9dc73db7))


### Bug Fixes

* **extension:** capture the page's own load-time GraphQL query ([#262](https://github.com/chrischall/fetchproxy/issues/262)) ([31990af](https://github.com/chrischall/fetchproxy/commit/31990afe9ee981cef025e8422fb47ff30e47a64a))
* **extension:** keep the Apollo accessor symmetric and re-wrap replaced clients ([#264](https://github.com/chrischall/fetchproxy/issues/264)) ([24bb28c](https://github.com/chrischall/fetchproxy/commit/24bb28ca1ee63ae590ee2c938f2074d05396ec78))
* **extension:** try every matching tab when a graphql op is unobserved ([#257](https://github.com/chrischall/fetchproxy/issues/257)) ([f62e3d9](https://github.com/chrischall/fetchproxy/commit/f62e3d9e447e23f0387a4d6752ec8c4abc1ddb81))

## [2.3.2](https://github.com/chrischall/fetchproxy/compare/v2.3.1...v2.3.2) (2026-08-31)


### Bug Fixes

* **extension:** honour each content script's matches when re-injecting ([#255](https://github.com/chrischall/fetchproxy/issues/255)) ([a3e9aa7](https://github.com/chrischall/fetchproxy/commit/a3e9aa74735398fd6d75bdb41c9cf780cc37bee0))

## [2.3.1](https://github.com/chrischall/fetchproxy/compare/v2.3.0...v2.3.1) (2026-08-31)


### Bug Fixes

* **extension:** re-inject content scripts after an update, not on next reload ([#251](https://github.com/chrischall/fetchproxy/issues/251)) ([57ff992](https://github.com/chrischall/fetchproxy/commit/57ff9923c41f3a82a9adf97a2f97b468e3a775aa))

## [2.3.0](https://github.com/chrischall/fetchproxy/compare/v2.2.1...v2.3.0) (2026-08-30)


### Features

* **extension:** open relay tabs in the background, in a fetchproxy tab group ([#247](https://github.com/chrischall/fetchproxy/issues/247)) ([1f125d5](https://github.com/chrischall/fetchproxy/commit/1f125d55f0f8483945d51f82caeb796c92808316)), closes [#248](https://github.com/chrischall/fetchproxy/issues/248)

## [2.2.1](https://github.com/chrischall/fetchproxy/compare/v2.2.0...v2.2.1) (2026-08-30)


### Bug Fixes

* **extension:** treat `www.` as optional when matching the relay tab ([#245](https://github.com/chrischall/fetchproxy/issues/245)) ([6dd0b25](https://github.com/chrischall/fetchproxy/commit/6dd0b250ef0d48d087269b7ae5cb11bc1a30d278))

## [2.2.0](https://github.com/chrischall/fetchproxy/compare/v2.1.0...v2.2.0) (2026-08-29)


### Features

* **server:** read the concentrator bind address from FETCHPROXY_WS_HOST ([#243](https://github.com/chrischall/fetchproxy/issues/243)) ([cd35384](https://github.com/chrischall/fetchproxy/commit/cd3538418ad68aab9a2f0ea48298994a193e0bcf))

## [2.1.0](https://github.com/chrischall/fetchproxy/compare/v2.0.0...v2.1.0) (2026-08-09)


### Features

* **extension:** dial configured remote bridges alongside loopback ([#233](https://github.com/chrischall/fetchproxy/issues/233)) ([cc81e8a](https://github.com/chrischall/fetchproxy/commit/cc81e8aa3f37b99f7445280f1f732c7cbb2768f8))
* **server:** fall back to FETCHPROXY_WS_PORT for the concentrator port ([#231](https://github.com/chrischall/fetchproxy/issues/231)) ([c221262](https://github.com/chrischall/fetchproxy/commit/c2212626385454918d7e6e319510849637e5bf14))


### Bug Fixes

* **extension:** give a refused hello its binding back, and show each bridge's own state ([#236](https://github.com/chrischall/fetchproxy/issues/236)) ([1f8da11](https://github.com/chrischall/fetchproxy/commit/1f8da11e77f97e8866bd53d69f6543058d490579)), closes [#234](https://github.com/chrischall/fetchproxy/issues/234)
* **extension:** refuse download over a remote bridge ([#235](https://github.com/chrischall/fetchproxy/issues/235)) ([306d1f5](https://github.com/chrischall/fetchproxy/commit/306d1f5a97348c4226eb36781cfc68c703a08594))


### Refactor

* **extension-core:** split background.ts into purpose-shaped modules ([#226](https://github.com/chrischall/fetchproxy/issues/226)) ([db30f4d](https://github.com/chrischall/fetchproxy/commit/db30f4d69dbcd30f10bce42c6a4dc4fee676207a)), closes [#10](https://github.com/chrischall/fetchproxy/issues/10)
* **extension-core:** stop exporting background helpers nothing imports ([#229](https://github.com/chrischall/fetchproxy/issues/229)) ([42c39a1](https://github.com/chrischall/fetchproxy/commit/42c39a1edeca447b86b045eaa266583aec02c501)), closes [#227](https://github.com/chrischall/fetchproxy/issues/227)

## [2.0.0](https://github.com/chrischall/fetchproxy/compare/v1.11.0...v2.0.0) (2026-08-06)


### ⚠ BREAKING CHANGES

* **protocol:** bind the ephemeral key into the ready signature ([#222](https://github.com/chrischall/fetchproxy/issues/222))

### Features

* **protocol:** add write_cookies, the one verb that can repair a rotated session ([#211](https://github.com/chrischall/fetchproxy/issues/211)) ([b2557c2](https://github.com/chrischall/fetchproxy/commit/b2557c2301fd624b65191200ac4f8026d9749230))
* **protocol:** bind the ephemeral key into the ready signature ([#222](https://github.com/chrischall/fetchproxy/issues/222)) ([c13aeed](https://github.com/chrischall/fetchproxy/commit/c13aeeddbf1bd2acf99e54116f2183772ffe1df1))
* **server:** let a request name the tab that relays it ([#207](https://github.com/chrischall/fetchproxy/issues/207)) ([c5d3f4d](https://github.com/chrischall/fetchproxy/commit/c5d3f4de113201c6fabf83794d012429740f9b6c))
* **server:** pin the extension's identity, and verify it on the peer path ([#213](https://github.com/chrischall/fetchproxy/issues/213)) ([0eeced7](https://github.com/chrischall/fetchproxy/commit/0eeced79b90acf23b79ae0349f156bdef725ae59))


### Bug Fixes

* **cli:** let a real filesystem error be itself, not "no extension pin" ([#221](https://github.com/chrischall/fetchproxy/issues/221)) ([c87a864](https://github.com/chrischall/fetchproxy/commit/c87a8644b8fa7fd603f5db161bb6c2d9632d24a3)), closes [#220](https://github.com/chrischall/fetchproxy/issues/220)
* **cli:** validate --via-tab before connecting, like the request URL ([#210](https://github.com/chrischall/fetchproxy/issues/210)) ([959fcc5](https://github.com/chrischall/fetchproxy/commit/959fcc5a88e7815a6b03342ff72ed0ef54b11578))
* **extension:** reattach the write_cookies doc block, and name the writable cookies as writable ([#215](https://github.com/chrischall/fetchproxy/issues/215)) ([2730c4a](https://github.com/chrischall/fetchproxy/commit/2730c4ad3170f1cee2c96ca55089e193cbc6e749))
* **extension:** use the guarded caps local for the cookie heading ([#217](https://github.com/chrischall/fetchproxy/issues/217)) ([f95c832](https://github.com/chrischall/fetchproxy/commit/f95c832eebabce28cbe39b4f6400d85f97de7cb9))
* **server:** release only our own extension claim, and stop guessing scoped names ([#219](https://github.com/chrischall/fetchproxy/issues/219)) ([3d90a64](https://github.com/chrischall/fetchproxy/commit/3d90a64049ab5b2c93076dd5fd297c771118fe30)), closes [#218](https://github.com/chrischall/fetchproxy/issues/218)
* **server:** type no-tab rejections so they stop reading as version mismatches ([#205](https://github.com/chrischall/fetchproxy/issues/205)) ([dc30bd9](https://github.com/chrischall/fetchproxy/commit/dc30bd9023d93872ead2c1597e52264b91b078a4))


### Refactor

* **server:** drop the concatBytes imports the signature change orphaned ([#224](https://github.com/chrischall/fetchproxy/issues/224)) ([4985ba7](https://github.com/chrischall/fetchproxy/commit/4985ba7b3475ea250000436e67ee76dab69eedb7)), closes [#223](https://github.com/chrischall/fetchproxy/issues/223)

## [1.11.0](https://github.com/chrischall/fetchproxy/compare/v1.10.0...v1.11.0) (2026-08-03)


### Features

* **protocol:** read path-scoped cookies via an explicit cookie path ([#199](https://github.com/chrischall/fetchproxy/issues/199)) ([143944e](https://github.com/chrischall/fetchproxy/commit/143944ec70f9c5a41803ed86fa5e559d45f55050))

## [1.10.0](https://github.com/chrischall/fetchproxy/compare/v1.9.1...v1.10.0) (2026-08-03)


### Features

* **server:** carry re-pair guidance on a typed scope error ([#196](https://github.com/chrischall/fetchproxy/issues/196)) ([63cbc2e](https://github.com/chrischall/fetchproxy/commit/63cbc2e9c851962fcbf11fa522f8cd72981ad56c))

## [1.9.1](https://github.com/chrischall/fetchproxy/compare/v1.9.0...v1.9.1) (2026-08-03)


### Documentation

* **bootstrap:** point the module header at createSessionLifter ([#193](https://github.com/chrischall/fetchproxy/issues/193)) ([81334fa](https://github.com/chrischall/fetchproxy/commit/81334fa0dc27a23847f2e84b8dc11fa68c44595e)), closes [#192](https://github.com/chrischall/fetchproxy/issues/192)

## [1.9.0](https://github.com/chrischall/fetchproxy/compare/v1.8.0...v1.9.0) (2026-08-02)


### Features

* **bootstrap:** add createSessionLifter for renewable session lifts ([#191](https://github.com/chrischall/fetchproxy/issues/191)) ([b2c7049](https://github.com/chrischall/fetchproxy/commit/b2c7049ac7441f063522c5c1d62cc358e3bde631))


### Bug Fixes

* **cli:** catch every gate-[#2](https://github.com/chrischall/fetchproxy/issues/2) scope rejection, not just three ([#187](https://github.com/chrischall/fetchproxy/issues/187)) ([b2ecced](https://github.com/chrischall/fetchproxy/commit/b2ecced564969cef0576d27e1fe5475b0eed7529)), closes [#185](https://github.com/chrischall/fetchproxy/issues/185)

## [1.8.0](https://github.com/chrischall/fetchproxy/compare/v1.7.0...v1.8.0) (2026-08-02)


### Features

* **bootstrap,cli:** surface partial lifts and clarify bridge errors ([#184](https://github.com/chrischall/fetchproxy/issues/184)) ([d1042a1](https://github.com/chrischall/fetchproxy/commit/d1042a19b1f3dbe52211ea01884726581f6ea824))

## [1.7.0](https://github.com/chrischall/fetchproxy/compare/v1.6.2...v1.7.0) (2026-07-29)


### Features

* **graphql:** route declared GraphQL ops through the tab's own Apollo client ([#178](https://github.com/chrischall/fetchproxy/issues/178)) ([0c3fdf4](https://github.com/chrischall/fetchproxy/commit/0c3fdf4e9d690c9f4250ea355729d494c1de8e8c))


### Bug Fixes

* **extension-chrome:** build content scripts as classic IIFE so Chrome injects them ([#175](https://github.com/chrischall/fetchproxy/issues/175)) ([f4a3728](https://github.com/chrischall/fetchproxy/commit/f4a37280094081465997aa62d7bf431f3fc94c6d))
* **graphql:** address all four tracked nits from PR [#178](https://github.com/chrischall/fetchproxy/issues/178)'s auto-review ([#180](https://github.com/chrischall/fetchproxy/issues/180)) ([9d88ac9](https://github.com/chrischall/fetchproxy/commit/9d88ac9adce4945c46ed82737c4464ae0ad427ca))

## [1.6.2](https://github.com/chrischall/fetchproxy/compare/v1.6.1...v1.6.2) (2026-07-27)


### Bug Fixes

* **cli:** validate profile array elements and name --storage-domain ([#173](https://github.com/chrischall/fetchproxy/issues/173)) ([871d87c](https://github.com/chrischall/fetchproxy/commit/871d87c248b3ac42b612a67c60b205cb86cce526))

## [1.6.1](https://github.com/chrischall/fetchproxy/compare/v1.6.0...v1.6.1) (2026-07-19)


### Documentation

* replace duplicated fleet policy with a pointer ([#168](https://github.com/chrischall/fetchproxy/issues/168)) ([15a413c](https://github.com/chrischall/fetchproxy/commit/15a413c74341e373d966c7199f068e61644d5f78))

## [1.6.0](https://github.com/chrischall/fetchproxy/compare/v1.5.1...v1.6.0) (2026-07-13)


### Features

* **cli:** add --version/-v flag and version in help header ([#159](https://github.com/chrischall/fetchproxy/issues/159)) ([b8a15b7](https://github.com/chrischall/fetchproxy/commit/b8a15b7b031aedc7b98442d9324b39ad39617c64))
* **cli:** add dom and download verbs ([#161](https://github.com/chrischall/fetchproxy/issues/161)) ([d6c1645](https://github.com/chrischall/fetchproxy/commit/d6c1645cd31f446c118ab114afa2eb072d64ad1b))


### Bug Fixes

* **cli:** upsert domSelectors on profile declare instead of dedup-only ([#163](https://github.com/chrischall/fetchproxy/issues/163)) ([2f2d9d3](https://github.com/chrischall/fetchproxy/commit/2f2d9d32224fd73d3bbaf232ed1f6dc819e4b3ce)), closes [#162](https://github.com/chrischall/fetchproxy/issues/162)
* **extension-core:** match vendor subdomains on read_dom tabs ([#164](https://github.com/chrischall/fetchproxy/issues/164)) ([5db6122](https://github.com/chrischall/fetchproxy/commit/5db61226e0ad085a53746ecbc16d36669261b51e))

## [1.5.1](https://github.com/chrischall/fetchproxy/compare/v1.5.0...v1.5.1) (2026-07-13)


### Bug Fixes

* publish @fetchproxy/cli in the release job + sync its dep ranges ([#157](https://github.com/chrischall/fetchproxy/issues/157)) ([40a4610](https://github.com/chrischall/fetchproxy/commit/40a4610b02a33fe0bb08565e3359ec0fbdce9967))

## [1.5.0](https://github.com/chrischall/fetchproxy/compare/v1.4.0...v1.5.0) (2026-07-13)


### Features

* **cli:** @fetchproxy/cli one-shot bridge CLI (fpx) ([#151](https://github.com/chrischall/fetchproxy/issues/151)) ([e0cb846](https://github.com/chrischall/fetchproxy/commit/e0cb846a99c7aebe84fa17b856ac36a3db25eedc))

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
