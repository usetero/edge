# Changelog

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
