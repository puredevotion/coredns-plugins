# Changelog

## [0.4.1](https://github.com/puredevotion/coredns-plugins/compare/v0.4.0...v0.4.1) (2026-08-03)


### Bug Fixes

* **ci:** nightly still pinned golangci-lint v1, so it never linted anything ([#39](https://github.com/puredevotion/coredns-plugins/issues/39)) ([33e66b3](https://github.com/puredevotion/coredns-plugins/commit/33e66b3b8f39ac229e2b46abd93742977acaefb7))

## [0.4.0](https://github.com/puredevotion/coredns-plugins/compare/v0.3.0...v0.4.0) (2026-08-02)


### Features

* **probe:** publish zone/wildcard so rrl can actually rate-limit this zone ([#37](https://github.com/puredevotion/coredns-plugins/issues/37)) ([87265bf](https://github.com/puredevotion/coredns-plugins/commit/87265bf90dd623e5a289784e3e5f37f18c2ee742))

## [0.3.0](https://github.com/puredevotion/coredns-plugins/compare/v0.2.0...v0.3.0) (2026-08-02)


### Features

* **dynupdate:** RFC 2136 dynamic update plugin, TSIG-gated ([#33](https://github.com/puredevotion/coredns-plugins/issues/33)) ([8c3a364](https://github.com/puredevotion/coredns-plugins/commit/8c3a364c58ea22d67e19e137653c0f4777b0a9b5))
* **probe:** run the RFC 9567 receiver, not just the parser ([#35](https://github.com/puredevotion/coredns-plugins/issues/35)) ([bb1676a](https://github.com/puredevotion/coredns-plugins/commit/bb1676af7b2ca2e149754a8f501370b98c32e556))

## [0.2.0](https://github.com/puredevotion/coredns-plugins/compare/v0.1.0...v0.2.0) (2026-08-01)


### Features

* **ci:** compile in upstream coredns/rrl, pinned as an external plugin ([#23](https://github.com/puredevotion/coredns-plugins/issues/23)) ([d0a2d6f](https://github.com/puredevotion/coredns-plugins/commit/d0a2d6f3aacc0acd1cd2b785376663bef74b04b7))
* **ci:** heavy-tier DevSecOps gate, sni_tls strict mode, golangci-lint v2 ([#19](https://github.com/puredevotion/coredns-plugins/issues/19)) ([7bfbe94](https://github.com/puredevotion/coredns-plugins/commit/7bfbe949be1b67def7b0d8826067e62d333a70df))
* **ci:** setcap cap_net_bind_service too, alongside cap_net_raw ([#11](https://github.com/puredevotion/coredns-plugins/issues/11)) ([70de4bd](https://github.com/puredevotion/coredns-plugins/commit/70de4bd3577e315ba1550f946b9439f623a64f5a))
* import sni_tls and radnr plugins ([06a2577](https://github.com/puredevotion/coredns-plugins/commit/06a2577bb3fb979e18d21012fe78ca0c1367fec9))
* **probe:** DELEG/CO/ECS three-state, RFC 9567, 9660, 8145, 9539, 8914 and ECH ([#27](https://github.com/puredevotion/coredns-plugins/issues/27)) ([cbcc9ea](https://github.com/puredevotion/coredns-plugins/commit/cbcc9ea625ee50d2a40dcf81787b46594ae68125))
* **probe:** per-visitor DNS measurement zone that can answer wrong on purpose ([#21](https://github.com/puredevotion/coredns-plugins/issues/21)) ([412601f](https://github.com/puredevotion/coredns-plugins/commit/412601fed731d7607e8bc4c243ed3a4f10a054b3))
* **probe:** serve a per-visitor RFC 6763 DNS-SD browse tree ([#28](https://github.com/puredevotion/coredns-plugins/issues/28)) ([fd018a6](https://github.com/puredevotion/coredns-plugins/commit/fd018a67323b159e4cc1847548f26066ebdeafd1))
* **sni_tls:** poll-based cert hot-reload ([21d6a3d](https://github.com/puredevotion/coredns-plugins/commit/21d6a3da17fa43f4bc36e067f91653679816cee5))


### Bug Fixes

* **ci:** apt over https, dagger engine egress policy blocks port 80 ([#9](https://github.com/puredevotion/coredns-plugins/issues/9)) ([f9b1885](https://github.com/puredevotion/coredns-plugins/commit/f9b1885d6d1c2c1b9965e7776c46fc7c508cecf1))
* **ci:** CGO_ENABLED=0 in BuildCoredns, static binary for distroless/static ([#4](https://github.com/puredevotion/coredns-plugins/issues/4)) ([0a33bff](https://github.com/puredevotion/coredns-plugins/commit/0a33bfff81f5f86e0bb8cb79f0fe95fd1b04a8e8))
* **ci:** combine apt-get update+install, stale dagger engine cache ([#6](https://github.com/puredevotion/coredns-plugins/issues/6)) ([93c8927](https://github.com/puredevotion/coredns-plugins/commit/93c89279273613ff246b31d117b551e315a3a095))
* **ci:** Dagger LintPlugin still on golangci-lint v1, cannot read a v2 config ([#24](https://github.com/puredevotion/coredns-plugins/issues/24)) ([b330ef2](https://github.com/puredevotion/coredns-plugins/commit/b330ef2e00d987dd78368c22357740c9b41c4bde))
* **ci:** force apt to IPv4, deb.debian.org IPv6 unreachable in this runner ([#7](https://github.com/puredevotion/coredns-plugins/issues/7)) ([f53aca8](https://github.com/puredevotion/coredns-plugins/commit/f53aca86192cd4ed3608485c63c9e95017d9592d))
* **ci:** force x/text 0.39.0 + grpc 1.82.1 in the built coredns binary ([#12](https://github.com/puredevotion/coredns-plugins/issues/12)) ([efb186f](https://github.com/puredevotion/coredns-plugins/commit/efb186f0a40720b16216d34ef546523c4962bb1c))
* **ci:** retry apt update+install, deb.debian.org flaky in this env ([#8](https://github.com/puredevotion/coredns-plugins/issues/8)) ([bdb792a](https://github.com/puredevotion/coredns-plugins/commit/bdb792a7d19da500fd8cdff8fd98ae5f8bf692bd))
* **ci:** setcap cap_net_raw+ep on the coredns binary, ambient set gap ([#5](https://github.com/puredevotion/coredns-plugins/issues/5)) ([f486df4](https://github.com/puredevotion/coredns-plugins/commit/f486df416ca8aaa34f9e5119c738f589329cbd78))
* **ci:** use non-private hostname in wildcard SNI test fixture ([5bd3752](https://github.com/puredevotion/coredns-plugins/commit/5bd3752809ae619cb78b1e790c900bda3788df1c))
* **deps:** bump the toolchain directive to go1.26.5 for three stdlib advisories ([d3ef0db](https://github.com/puredevotion/coredns-plugins/commit/d3ef0db5c792fbdaa208c02641204a5034823567))
* **deps:** bump x/text and grpc for two High-severity advisories ([462e7d4](https://github.com/puredevotion/coredns-plugins/commit/462e7d47dfb7c673efa6421ebf3d455056221d2d))
* **deps:** bump x/text and grpc for two High-severity advisories ([674a420](https://github.com/puredevotion/coredns-plugins/commit/674a420a3b46c37f989811ba7ea290ae5906e3e2))
* **deps:** tidy radnr and sni_tls, main CI has been red since the x/text bump ([#30](https://github.com/puredevotion/coredns-plugins/issues/30)) ([8ee6701](https://github.com/puredevotion/coredns-plugins/commit/8ee67012b9375d34001bc5ef1dfb43b147fe4aa7))
* **deps:** update patch/minor dependency updates ([#14](https://github.com/puredevotion/coredns-plugins/issues/14)) ([e5e28e9](https://github.com/puredevotion/coredns-plugins/commit/e5e28e9f5929520584fdf4c6eb5572206f5c90d4))
* **sni_tls:** match RFC 6125 single-level wildcard certs by SNI ([#10](https://github.com/puredevotion/coredns-plugins/issues/10)) ([1dd8cc7](https://github.com/puredevotion/coredns-plugins/commit/1dd8cc779c503fef9eee49bfd3c1d9e04369b431))
