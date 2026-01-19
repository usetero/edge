# Changelog

## [1.12.1](https://github.com/usetero/edge/compare/v1.12.0...v1.12.1) (2026-01-19)


### Bug Fixes

* patch const cast issue and build safe in signoff ([#94](https://github.com/usetero/edge/issues/94)) ([ff24d43](https://github.com/usetero/edge/commit/ff24d436f01c8d6cff8f7ae9d563c0787e851382))

## [1.12.0](https://github.com/usetero/edge/compare/v1.11.0...v1.12.0) (2026-01-19)


### Features

* add in prometheus distro ([#91](https://github.com/usetero/edge/issues/91)) ([88d209e](https://github.com/usetero/edge/commit/88d209e63d5da68f4a5a7d80afd379e9859eecb9))
* implement span policies in edge ([#89](https://github.com/usetero/edge/issues/89)) ([b6af192](https://github.com/usetero/edge/commit/b6af1925d2be8dd618c47dab587a21825e738074))
* support policy stages ([#93](https://github.com/usetero/edge/issues/93)) ([3d98eed](https://github.com/usetero/edge/commit/3d98eed280778da1b68dc6d64441d5f4d5096eaf))


### Bug Fixes

* clean up workspace id requirement and a compression issue ([#92](https://github.com/usetero/edge/issues/92)) ([44b2775](https://github.com/usetero/edge/commit/44b277531dfdde354d608ce8890cf7485a8e6e5c))

## [1.11.0](https://github.com/usetero/edge/compare/v1.10.1...v1.11.0) (2026-01-13)


### Features

* support environment variable substitution ([#84](https://github.com/usetero/edge/issues/84)) ([6987f16](https://github.com/usetero/edge/commit/6987f16cec57c2d8456ae15fb5ba6e944e37ade0))


### Bug Fixes

* add ignore unknown ([#87](https://github.com/usetero/edge/issues/87)) ([2532b27](https://github.com/usetero/edge/commit/2532b2772dd21a5f24c63c5cf9d23bab1683282a))

## [1.10.1](https://github.com/usetero/edge/compare/v1.10.0...v1.10.1) (2026-01-07)


### Bug Fixes

* support exists false ([#78](https://github.com/usetero/edge/issues/78)) ([35a8ae8](https://github.com/usetero/edge/commit/35a8ae8e1fd6d89be2b7394fe2eebb0da9d77833))

## [1.10.0](https://github.com/usetero/edge/compare/v1.9.0...v1.10.0) (2026-01-06)


### Features

* attempt releasing binaries too ([#77](https://github.com/usetero/edge/issues/77)) ([f3ab4ab](https://github.com/usetero/edge/commit/f3ab4abd3d912e99294d8f998a44b80e5cd73254))
* perf improvements and benchmark comparisons ([#74](https://github.com/usetero/edge/issues/74)) ([5bfe030](https://github.com/usetero/edge/commit/5bfe030f3253603962cbc9ee301dcc68114aa253))
* update docs and releases for catchall ([#76](https://github.com/usetero/edge/issues/76)) ([e940ba6](https://github.com/usetero/edge/commit/e940ba6d498e0747c7601fc0ec1fee577f6d09b7))

## [1.9.0](https://github.com/usetero/edge/compare/v1.8.1...v1.9.0) (2026-01-02)


### Features

* better exports and lower matching policy limit ([#73](https://github.com/usetero/edge/issues/73)) ([a3b3a0d](https://github.com/usetero/edge/commit/a3b3a0d2e5fbde23554423f7f465def30cdc33d5))
* support for sampling and rate limits ([#71](https://github.com/usetero/edge/issues/71)) ([77aace7](https://github.com/usetero/edge/commit/77aace7adeef021763948b67b941069a09446709))

## [1.8.1](https://github.com/usetero/edge/compare/v1.8.0...v1.8.1) (2025-12-31)


### Bug Fixes

* add health checks for the edge ([#66](https://github.com/usetero/edge/issues/66)) ([173095a](https://github.com/usetero/edge/commit/173095a52409974fca4c68982f2363396cd573e6))
* bot signoff work plz ([#68](https://github.com/usetero/edge/issues/68)) ([2a6a90e](https://github.com/usetero/edge/commit/2a6a90e99d8c4bc4d2aa67165ebbcb42ae4532b2))
* maybe signoff will work ([#69](https://github.com/usetero/edge/issues/69)) ([78b6a51](https://github.com/usetero/edge/commit/78b6a5153680126c32c8624b6f25a6756d15cebe))

## [1.8.0](https://github.com/usetero/edge/compare/v1.7.0...v1.8.0) (2025-12-31)


### Features

* otlp metrics support ([#62](https://github.com/usetero/edge/issues/62)) ([7068b59](https://github.com/usetero/edge/commit/7068b594a556c618cdf5e7af6b212d43ad824ae3))
* support more fields in the protos ([#64](https://github.com/usetero/edge/issues/64)) ([ecf9d01](https://github.com/usetero/edge/commit/ecf9d0127c17af5ff4a1aa7ad98c404a8523d15b))

## [1.7.0](https://github.com/usetero/edge/compare/v1.6.0...v1.7.0) (2025-12-31)


### Features

* support metric transforms in the edge ([#61](https://github.com/usetero/edge/issues/61)) ([a419678](https://github.com/usetero/edge/commit/a41967847ebca47b4bc6f57bf986c27f3cfe4fcd))


### Bug Fixes

* proxy response was truncated and encoding when not requested ([#59](https://github.com/usetero/edge/issues/59)) ([2728ff6](https://github.com/usetero/edge/commit/2728ff63a79fafe1d29a63ca3b7f470a05f423c0))

## [1.6.0](https://github.com/usetero/edge/compare/v1.5.1...v1.6.0) (2025-12-24)


### Features

* accept log transform policies ([#54](https://github.com/usetero/edge/issues/54)) ([a6718b8](https://github.com/usetero/edge/commit/a6718b8fb474c6a2291c0a02370f9e84abb4de7c))
* report hits and misses for transforms ([#57](https://github.com/usetero/edge/issues/57)) ([375da93](https://github.com/usetero/edge/commit/375da9394726373981f12eb4ad3bf97d3705c8b7))


### Bug Fixes

* pin version for gh action ([#55](https://github.com/usetero/edge/issues/55)) ([4a5e6bc](https://github.com/usetero/edge/commit/4a5e6bc6072686f5552e05fe8db24ab361cc187e))

## [1.5.1](https://github.com/usetero/edge/compare/v1.5.0...v1.5.1) (2025-12-15)


### Bug Fixes

* read the full body with fetch ([#51](https://github.com/usetero/edge/issues/51)) ([61ff928](https://github.com/usetero/edge/commit/61ff928174a5bfcc08e476bd64513473cfa68683))

## [1.5.0](https://github.com/usetero/edge/compare/v1.4.0...v1.5.0) (2025-12-15)


### Features

* accept headers in config ([#49](https://github.com/usetero/edge/issues/49)) ([bf14083](https://github.com/usetero/edge/commit/bf14083cea7d0563d31ec6d8719ae389d87efff1))


### Bug Fixes

* remove wait ([#47](https://github.com/usetero/edge/issues/47)) ([24c2ad8](https://github.com/usetero/edge/commit/24c2ad8219f6d553a530b52b0ad032ebe8f45437))

## [1.4.0](https://github.com/usetero/edge/compare/v1.3.0...v1.4.0) (2025-12-15)


### Features

* continuous benchmarks ([#45](https://github.com/usetero/edge/issues/45)) ([289cbd1](https://github.com/usetero/edge/commit/289cbd1e83ce0936832968ad25e6bc8173d11f52))


### Bug Fixes

* benchmark gh action ([#46](https://github.com/usetero/edge/issues/46)) ([37f469d](https://github.com/usetero/edge/commit/37f469d45bb3c829c3241686d8d630e06ebe11ed))
* retry on connection issues ([#40](https://github.com/usetero/edge/issues/40)) ([8efea22](https://github.com/usetero/edge/commit/8efea22711b5434ab138bfc76e4443645ce21cce))

## [1.3.0](https://github.com/usetero/edge/compare/v1.2.2...v1.3.0) (2025-12-09)


### Features

* add in protobuf support ([#38](https://github.com/usetero/edge/issues/38)) ([c86b1c5](https://github.com/usetero/edge/commit/c86b1c501e4b61eed935780f9937b579c448cbb1))
* support otlp logs in the proxy ([#33](https://github.com/usetero/edge/issues/33)) ([b432018](https://github.com/usetero/edge/commit/b432018fe417642eefe5d3bd79f1617866bfe17a))


### Bug Fixes

* pin versions ([#39](https://github.com/usetero/edge/issues/39)) ([a770707](https://github.com/usetero/edge/commit/a7707074a4a1657d9656d0a33b43c5738e85150d))

## [1.2.2](https://github.com/usetero/edge/compare/v1.2.1...v1.2.2) (2025-12-08)


### Bug Fixes

* arm image not working on mac ([#31](https://github.com/usetero/edge/issues/31)) ([f450f7c](https://github.com/usetero/edge/commit/f450f7c69c85c6a3e1614f6524db7513df8f6a7e))

## [1.2.1](https://github.com/usetero/edge/compare/v1.2.0...v1.2.1) (2025-12-08)


### Bug Fixes

* dockerfile needs vectorscan dep ([#29](https://github.com/usetero/edge/issues/29)) ([5d40b18](https://github.com/usetero/edge/commit/5d40b1858fa760582f3346a47d7e56f71a959d8b))

## [1.2.0](https://github.com/usetero/edge/compare/v1.1.0...v1.2.0) (2025-12-08)


### Features

* use new arm runner for ci/cd ([#27](https://github.com/usetero/edge/issues/27)) ([1944a7b](https://github.com/usetero/edge/commit/1944a7bc6c35ffccca726b162102eeaf9a977dfe))

## [1.1.0](https://github.com/usetero/edge/compare/v1.0.0...v1.1.0) (2025-12-05)


### Features

* cross compile and fix linux bug ([#25](https://github.com/usetero/edge/issues/25)) ([6c9bd90](https://github.com/usetero/edge/commit/6c9bd90b6522266b038dbcccd88255376475f03e))
* fix build by prefetching deps ([#26](https://github.com/usetero/edge/issues/26)) ([03d7367](https://github.com/usetero/edge/commit/03d73676487d3228e4981e595bc47a437973a328))
* get release done ([#22](https://github.com/usetero/edge/issues/22)) ([1c4e0b2](https://github.com/usetero/edge/commit/1c4e0b209c700ae6112e70d5c3c8f5ecee0c4f04))
* push to ghcr instead ([#24](https://github.com/usetero/edge/issues/24)) ([de77e66](https://github.com/usetero/edge/commit/de77e666269e4b7d5d0223690a13222802d65847))

## 1.0.0 (2025-12-05)


### Features

* add in compression and decompression ([#5](https://github.com/usetero/edge/issues/5)) ([465f1bd](https://github.com/usetero/edge/commit/465f1bdd7d4a36af2b80bd37b868dbd5e26a8e78))
* add in logging observability system to edge ([#18](https://github.com/usetero/edge/issues/18)) ([1aea1b8](https://github.com/usetero/edge/commit/1aea1b8989ded59398c3fe0ad1a9ae0c1f67cd18))
* add release task ([#20](https://github.com/usetero/edge/issues/20)) ([659d9b6](https://github.com/usetero/edge/commit/659d9b62383ddbd989e8eb9a68c436e64bf8bfbe))
* apply policies using the evaluator ([#9](https://github.com/usetero/edge/issues/9)) ([9c0718b](https://github.com/usetero/edge/commit/9c0718b4a06e1b3fed65018af0db36db64c493eb))
* enable filter policies ([#4](https://github.com/usetero/edge/issues/4)) ([c91c02a](https://github.com/usetero/edge/commit/c91c02a9a05d243d3f91d77eb3e59530a90e3675))
* get it deployed ([#11](https://github.com/usetero/edge/issues/11)) ([78d6142](https://github.com/usetero/edge/commit/78d6142567b621c6c86f6a21a2a063efc699c774))
* implement hashing logic and properly send sync request ([#15](https://github.com/usetero/edge/issues/15)) ([8c3f3fc](https://github.com/usetero/edge/commit/8c3f3fce3451d8395d3716f03060fb6bc73857ac))
* implement hyperscan ([#14](https://github.com/usetero/edge/issues/14)) ([15b6a10](https://github.com/usetero/edge/commit/15b6a10fb70651061c74bce147bb0b32271d5848))
* improve hyperscan logic ([#17](https://github.com/usetero/edge/issues/17)) ([651a6d2](https://github.com/usetero/edge/commit/651a6d25018be2e6a7b0ca1722f1b55cabe04a5b))
* improve modularity and performance ([#10](https://github.com/usetero/edge/issues/10)) ([c920769](https://github.com/usetero/edge/commit/c920769c4a1df510f97e9a5ee1e5a5ff0f5310fd))
* install zig-proto to generate protos and create provider structure ([#6](https://github.com/usetero/edge/issues/6)) ([afe6068](https://github.com/usetero/edge/commit/afe606865ba4a5b788a905b3749c8e8bf9eedb56))
* proxy DD logs w/ passthrough ([#3](https://github.com/usetero/edge/issues/3)) ([e215db1](https://github.com/usetero/edge/commit/e215db15f45a3b9f29057784661b8ef324395b70))
* remove unused fields, minor refactor ([#16](https://github.com/usetero/edge/issues/16)) ([d5a2bb5](https://github.com/usetero/edge/commit/d5a2bb51295ae76c1af184454a18101991ab7b64))
* track policy states in the providers and refactoring for better structure ([#19](https://github.com/usetero/edge/issues/19)) ([250d8e3](https://github.com/usetero/edge/commit/250d8e33b161342ccf57aef3e2518a5cf905bd91))
* use new protos ([#12](https://github.com/usetero/edge/issues/12)) ([5882082](https://github.com/usetero/edge/commit/5882082d3ebea9aa444ecd7376c9e07210af13d5))
* use the new policy proto structure ([#13](https://github.com/usetero/edge/issues/13)) ([803dca6](https://github.com/usetero/edge/commit/803dca6db82785e3f8bff7cef99b6c25f3c3c887))
* use the shared protos ([#8](https://github.com/usetero/edge/issues/8)) ([afc9f0b](https://github.com/usetero/edge/commit/afc9f0bdfe5935f2d516a2e722f1dd565798fa7e))


### Bug Fixes

* migrate pretty print to new interface types ([#2](https://github.com/usetero/edge/issues/2)) ([720b6c6](https://github.com/usetero/edge/commit/720b6c6a1d2c99ad4050811a9de1f0b860463367))
* tests were borked with recent refactors ([#7](https://github.com/usetero/edge/issues/7)) ([efc9d3c](https://github.com/usetero/edge/commit/efc9d3c3ea8a3875384604a720f1c60ca5ef83da))
