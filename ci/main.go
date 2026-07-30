// Package main is this repository's Dagger CI module: test each plugin
// standalone, build a custom CoreDNS binary with the plugin(s) wired in via
// plugin.cfg, and package the resulting image. The build step is CoreDNS-
// specific (clone pinned upstream source, patch plugin.cfg, go generate)
// rather than a plain `go build`.
//
// Usage (local or in CI, same commands, run from ci/):
//
//	dagger call test-plugin    --source=.. --plugin-dir=sni_tls
//	dagger call lint-plugin    --source=.. --plugin-dir=sni_tls
//	dagger call gitleaks-scan  --source=.. --base=main
//	dagger call yaml-lint      --source=..
//	dagger call sbom-scan      --source=.. --plugin-dir=sni_tls
//	dagger call opengrep-scan  --source=..
//	dagger call build-coredns --source=.. --coredns-version=1.14.6
//	dagger call containerize  --source=.. --coredns-version=1.14.6 export --path=./coredns.tar
//
// Containerize returns the built OCI image as a tarball (Container.AsTarball),
// not a pushed registry ref. Pushing is deliberately left to the caller: a
// registry using mTLS client-cert authentication cannot be driven by Dagger's
// native withRegistryAuth, which only supports username/secret credentials.
// Deployers that need client-cert auth should push as a separate step with
// oras/skopeo and a mounted client cert. Containerize's job ends at "here is
// the image", not "here it is in a registry".
package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"dagger/coredns-plugins-ci/internal/dagger"
)

// CorednsPluginsCi is the CI module root.
type CorednsPluginsCi struct{}

// plugins lists every plugin this module knows how to wire into a CoreDNS
// build, and where each replaces/inserts into plugin.cfg.
//
//   - sni_tls REPLACES the stock tls:tls line (same slot: it configures the
//     listener's TLS before any query-handling plugin runs, same as stock tls).
//   - radnr is listener-only (no ServeDNS, like health/metrics) so its slot in
//     the chain doesn't matter for query handling; placed next to health/ready
//     for locality with the other listener-only plugins.
//   - rrl is NOT ours (see externalVersion) — it's upstream's own external
//     plugin, wired in by module path instead of vendored source.
var pluginCfgPatches = map[string]struct {
	// cfgLine is the plugin.cfg line to insert (or use as replacement value).
	cfgLine string
	// replaceStockLine, if non-empty, is the exact stock plugin.cfg line this
	// plugin's line replaces (sed s/replaceStockLine/cfgLine/).
	replaceStockLine string
	// insertAfterLine, if non-empty (and replaceStockLine is empty), is the
	// stock plugin.cfg line this plugin's line is inserted immediately after.
	insertAfterLine string
	modulePath      string // Go import path used in plugin.cfg + go.mod replace
	// externalModule, if non-empty, marks this as a THIRD-PARTY plugin that
	// does not live in this repo: there is no directory at the repo root to
	// vendor in and no go.mod replace directive, so BuildCoredns resolves it
	// with `go get externalModule@externalVersion` instead.
	//
	// This is the MODULE root path, which is not always modulePath: modulePath
	// is the package import path plugin.cfg needs (…/rrl/plugins/rrl) while
	// `go get` takes the module (…/rrl). Kept as two explicit fields rather
	// than derived, because there is no general rule for where a module path
	// ends and a package path begins.
	externalModule string
	// externalVersion is the exact version for externalModule — never
	// "latest". A floating external dependency would mean the shipped binary's
	// behavior could change between two builds of the same commit, which is
	// the one thing every other pin in this file exists to prevent. Renovate
	// tracks it like any other Go dependency.
	//
	// Consequence for the rest of this file: such plugins have no local source
	// to test, lint, or SBOM-scan as a plugin directory (the consuming CI's
	// per-plugin loop enumerates our own dirs only) — but they ARE part of the
	// built binary, so the binary-level SBOM/vuln scan and Containerize's
	// `-plugins` smoke test still cover them.
	externalVersion string
}{
	"sni_tls": {
		cfgLine:          "sni_tls:github.com/puredevotion/coredns-plugins/sni_tls",
		replaceStockLine: "tls:tls",
		modulePath:       "github.com/puredevotion/coredns-plugins/sni_tls",
	},
	"radnr": {
		cfgLine:         "radnr:github.com/puredevotion/coredns-plugins/radnr",
		insertAfterLine: "health:health",
		modulePath:      "github.com/puredevotion/coredns-plugins/radnr",
	},
	// Response Rate Limiting — the amplification-abuse mitigation that gates
	// any public exposure of an authoritative zone we serve (homelab
	// docs/plans/authoritative-dns-hivre.md Phase 2). That plan assumed this
	// had to be written from scratch, having only checked CoreDNS's in-tree
	// plugin.cfg; it exists as an external plugin under the coredns org
	// itself, Apache-2.0, and already implements exactly what the plan
	// specified (per-client-prefix tracking, TC=1 slip, exported counters).
	// Adopted rather than reimplemented: this is the one safety-critical
	// piece, so the widely-reviewed implementation wins over ours.
	//
	// Slot per upstream's own plugin.cfg.yaml (landmark "acl", after: false)
	// => immediately BEFORE acl:acl, which in v1.14.6's plugin.cfg is
	// immediately after rewrite:rewrite. Rate limiting must sit ahead of the
	// plugins that actually answer, so a limited response is never generated
	// in the first place.
	//
	// Verified 2026-07-30 against v1.14.6: upstream rrl's own go.mod pins
	// coredns v1.12.4, two minors behind ours, so this was a real
	// question — a clean build + `-plugins` listing rrl confirmed the plugin
	// API it uses is unchanged across that gap.
	// The per-visitor DNS measurement zone for the hivre.com lab. An
	// authoritative backend, so it belongs among the other backends and after
	// rrl — rate limiting has to see a query before anything answers it.
	// Slotted next to `file` because that is the closest analogue: both are
	// authoritative sources of truth for a zone, one from disk and one
	// synthesized.
	"probe": {
		cfgLine:         "probe:github.com/puredevotion/coredns-plugins/probe",
		insertAfterLine: "file:file",
		modulePath:      "github.com/puredevotion/coredns-plugins/probe",
	},
	"rrl": {
		cfgLine:         "rrl:github.com/coredns/rrl/plugins/rrl",
		insertAfterLine: "rewrite:rewrite",
		modulePath:      "github.com/coredns/rrl/plugins/rrl",
		externalModule:  "github.com/coredns/rrl",
		externalVersion: "v0.0.0-20250915113509-ac1135e077ba",
	},
}

// goBase returns a Go build container with the plugin source copied in and
// module cache wired to a persistent Dagger cache volume (shared across runs
// on the engine, same convention as ci/dagger/main.go's goBase).
//
// WithDirectory (copy), not WithMountedDirectory (bind mount), for `source`:
// per BuildKit's own documented behavior (see dagger/dagger#6421), a mounted
// directory only gets content-hash cache validation when it is BOTH a
// non-root mount AND read-only; a plain writable WithMountedDirectory (what
// every call site here used before) skips that check entirely and can
// legally reuse a cached downstream layer even when the mounted content
// actually changed. WithDirectory copies the content into the container's
// own filesystem layer instead, which is always content-addressed like any
// other layer -- no such carve-out. This is the suspected mechanism behind
// coredns-radnr's 539a57a incident (deployment.yaml's own history note): a
// pod found live serving a cert for an SNI name absent from its Corefile,
// root-caused at the time only as far as "stale/cached vendored-source
// layer." BuildCoredns's vendored-plugin mount (below) is the highest-stakes
// instance of this same pattern -- it's what actually ends up compiled into
// the shipped binary.
func (m *CorednsPluginsCi) goBase(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From("golang:1.26").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("go-build")).
		WithDirectory("/src", source).
		WithWorkdir("/src")
}

// TestPlugin runs a single plugin's Go test suite standalone (fast iteration
// loop, before wiring it into a full CoreDNS build). `pluginDir` is the
// plugin's directory at the repo root (e.g. sni_tls). `source` is the REPO
// ROOT, matching BuildCoredns's convention, so the plugin lives at
// /src/<pluginDir> under the mount. Passing a subdirectory instead of the repo
// root was a real bug once: it failed with "pattern ./...: directory prefix .
// does not contain main module".
func (m *CorednsPluginsCi) TestPlugin(ctx context.Context, source *dagger.Directory, pluginDir string) (string, error) {
	return m.goBase(source).
		WithWorkdir("/src/" + pluginDir).
		WithExec([]string{"go", "test", "-race", "./..."}).
		Stdout(ctx)
}

// golangciLintImage is pinned like every other tool image in this ecosystem —
// a floating tag would mean a lint pass silently starts catching (or missing)
// different things between runs. Same linter set (.golangci.yml: govet,
// staticcheck, errcheck, gosec) as dafs's ci/ module and homelab's
// ci/dagger + experiments/ra-dnr — one consistent Go lint/SAST bar across
// every Go repo in this ecosystem, public or not.
//
// v2, and it MUST stay >= the Go version the plugin go.mod files target.
// golangci-lint refuses to load a config when its own build's Go version is
// older than the target: "the Go language version (go1.23) used to build
// golangci-lint is lower than the targeted Go version (1.26.5)". No v1.x
// release is built against Go 1.26, so v1 stopped being viable the moment
// those go.mod toolchains moved past 1.24 — and .golangci.yml is on the v2
// schema now, which a v1 binary could not read either. The two move together.
//
// This lagged behind .github/workflows/ci.yml, which was migrated to v2.12.2
// while this constant stayed on v1.62.2. Nothing caught it because the two
// lint paths are exercised by different pipelines: the workflow lints on every
// push here, whereas this Dagger entry point only runs from homelab's
// ci-coredns-plugins job, which fires on a flake.lock bump. The next such bump
// failed on sni_tls before it ever reached the new plugin. Keep this in step
// with that workflow's `version:` pin.
const golangciLintImage = "golangci/golangci-lint:v2.12.2-alpine"

// LintPlugin runs golangci-lint on the plugin. Upgraded from a bare `go vet`
// (which only ever caught the small, non-security subset go vet's analyzers
// cover) — golangci-lint's config lives at the repo root and is picked up
// automatically since golangci-lint walks up from the working directory to
// find it. See TestPlugin's doc comment for the source-root path convention.
func (m *CorednsPluginsCi) LintPlugin(ctx context.Context, source *dagger.Directory, pluginDir string) (string, error) {
	return dag.Container().
		From(golangciLintImage).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("go-build")).
		WithMountedCache("/root/.cache/golangci-lint", dag.CacheVolume("golangci-lint")).
		WithDirectory("/src", source).
		WithWorkdir("/src/" + pluginDir).
		WithExec([]string{"golangci-lint", "run", "--timeout=5m", "./..."}).
		Stdout(ctx)
}

// gitleaksImage pinned to the same release dafs's own gitleaks job uses —
// kept in lockstep across the ecosystem for the same reason every other
// pinned tool here is: a version drift between repos is a real disagreement
// worth noticing, not something that should happen silently.
const gitleaksImage = "ghcr.io/gitleaks/gitleaks:v8.30.1"

// GitleaksScan scans `base..HEAD` for hardcoded secrets. This repo had no
// secret scanning at all before this — `base` defaults to "main" if empty,
// matching the convention dafs/homelab both use for the same reason: a local
// `dagger call` has no PR context to read a base ref from.
func (m *CorednsPluginsCi) GitleaksScan(ctx context.Context, source *dagger.Directory, base string) (string, error) {
	if base == "" {
		base = "main"
	}

	return dag.Container().
		From(gitleaksImage).
		WithDirectory("/src", source).
		WithWorkdir("/src").
		WithExec([]string{"gitleaks", "git", "--log-opts=" + base + "..HEAD", "--redact", "--no-banner", "."}).
		Stdout(ctx)
}

// YamlLint asserts every workflow file is yamllint-clean, using the repo
// root's .yamllint.yml (relaxed line-length/document-start — see that file's
// comments for why).
func (m *CorednsPluginsCi) YamlLint(ctx context.Context, source *dagger.Directory) (string, error) {
	return dag.Container().
		From("alpine:3.21").
		WithExec([]string{"apk", "add", "--no-cache", "yamllint"}).
		WithDirectory("/src", source).
		WithWorkdir("/src").
		WithExec([]string{"yamllint", "-c", ".yamllint.yml", "-f", "parsable", ".github/workflows"}).
		Stdout(ctx)
}

// cyclonedxGomodVersion is pinned for the same reproducibility reason as
// every other tool version in this file.
const cyclonedxGomodVersion = "v1.7.0"

// Sbom generates a CycloneDX SBOM for `pluginDir`'s Go module graph.
//
// `mod` rather than `app` or `bin`: these plugins are libraries wired into a
// CoreDNS binary elsewhere (BuildCoredns), not built as standalone binaries
// in their own right, so there is no `main` package here for cyclonedx-gomod
// to build against — `mod` reads go.mod/go.sum directly, which is the
// property this SBOM actually needs to describe (mirrors dafs's Sbom, which
// is likewise a manifest-graph SBOM via cargo-cyclonedx, not a binary scan).
func (m *CorednsPluginsCi) Sbom(ctx context.Context, source *dagger.Directory, pluginDir string) *dagger.File {
	container := m.goBase(source).
		WithWorkdir("/src/" + pluginDir).
		WithExec([]string{"go", "install",
			"github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@" + cyclonedxGomodVersion}).
		WithExec([]string{"sh", "-c",
			`$(go env GOPATH)/bin/cyclonedx-gomod mod -json -output /tmp/sbom.cdx.json`})
	return container.File("/tmp/sbom.cdx.json")
}

// SbomScan generates the CycloneDX SBOM (Sbom) for `pluginDir` and scans it
// with grype, matching dafs's SbomScan and the grype version homelab's own
// deploy-side pipeline already pins.
func (m *CorednsPluginsCi) SbomScan(ctx context.Context, source *dagger.Directory, pluginDir string) (string, error) {
	sbom := m.Sbom(ctx, source, pluginDir)

	return dag.Container().
		From("alpine:3.21").
		WithExec([]string{"apk", "add", "--no-cache", "curl", "bash", "ca-certificates"}).
		WithExec([]string{"sh", "-c",
			"curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v0.116.0"}).
		WithFile("/sbom.cdx.json", sbom).
		WithExec([]string{"grype", "sbom:/sbom.cdx.json", "--fail-on", "high"}).
		Stdout(ctx)
}

// opengrepVersion pins the same Opengrep release homelab's ci/dagger module
// already uses — one version across the ecosystem, same reasoning as every
// other pinned tool here.
const opengrepVersion = "v1.25.0"

// OpengrepScan runs Opengrep (the OSS fork of Semgrep) against this repo's Go
// source — broad static-analysis coverage beyond golangci-lint's gosec linter
// (injection, unsafe deserialization, hardcoded crypto, etc.), same tool and
// invocation shape as homelab's own OpengrepScan.
func (m *CorednsPluginsCi) OpengrepScan(ctx context.Context, source *dagger.Directory) (string, error) {
	bin := dag.HTTP("https://github.com/opengrep/opengrep/releases/download/" + opengrepVersion + "/opengrep_manylinux_x86")
	rules := dag.Git("https://github.com/opengrep/opengrep-rules.git").Branch("main").Tree()
	return dag.Container().
		From("debian:12-slim").
		// debian-slim ships no locale → Python's read_text() falls back to
		// ASCII and dies on UTF-8 bytes in the rule files. Force UTF-8 mode
		// (same fix homelab's OpengrepScan needed for the same reason).
		WithEnvVariable("PYTHONUTF8", "1").
		WithEnvVariable("LC_ALL", "C.UTF-8").
		WithFile("/usr/local/bin/opengrep", bin, dagger.ContainerWithFileOpts{Permissions: 0o755}).
		WithDirectory("/rules", rules).
		WithDirectory("/src", source).
		WithWorkdir("/src").
		WithExec([]string{"opengrep", "scan", "-f", "/rules/go", "--error", "."}).
		Stdout(ctx)
}

// buildBase returns a container with git+bash (needed for the clone + sed
// patch + go generate steps) and the Go module/build caches wired, matching
// goBase's cache convention.
func (m *CorednsPluginsCi) buildBase() *dagger.Container {
	return dag.Container().
		From("golang:1.26").
		// The actual root cause of three straight failed theories (stale
		// cache, IPv6-only, "flaky mirror"): this container runs inside the
		// shared Dagger engine, which k8s/dagger/networkpolicy.yaml in the
		// consuming homelab repo deliberately fences to egress on port 443
		// only (issue #27, "fence the privileged Dagger engine") plus a
		// scoped hole to the internal Zot registry. golang:1.26's default
		// apt sources point at http://deb.debian.org (port 80), which that
		// policy actively refuses -- "Connection refused" on every mirror
		// IP, every time, is a NetworkPolicy doing exactly its job, not
		// flakiness. Rewriting the sources to https (still deb.debian.org,
		// just the port the policy already allows) is the actual fix --
		// classic and deb822-format sources files both handled since
		// Debian's default format changed to deb822 in trixie.
		//
		// libcap2-bin: setcap, used after the build to grant cap_net_raw to
		// the binary itself (see BuildCoredns) so radnr's raw ICMPv6 socket
		// works for the nonroot user this image runs as.
		WithExec([]string{"sh", "-c", `
			sed -i 's|http://deb.debian.org|https://deb.debian.org|g' \
				/etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null
			apt-get update && apt-get install -y --no-install-recommends git libcap2-bin
		`}).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("go-build")).
		// golang:1.26 ships gcc, so cgo defaults on and go build produces a
		// dynamically-linked binary. Containerize packages that binary onto
		// distroless/static, which has no libc at all — the runtime symptom
		// is `exec /coredns: no such file or directory` (the missing ELF
		// interpreter, not a missing file). Force a static binary instead.
		WithEnvVariable("CGO_ENABLED", "0")
}

// BuildCoredns clones the pinned upstream CoreDNS tag, patches plugin.cfg to
// wire in every plugin the module knows about (see pluginCfgPatches), resolves
// each one — a go.mod replace directive pointing at vendored source from
// `source` for our own plugins, a pinned `go get` for third-party ones — runs
// `go generate` (regenerates zplugin.go/zdirectives.go per coredns.go's
// //go:generate directives), and builds the coredns binary. Returns the
// built binary as a File so Containerize can wrap it into a runtime image.
func (m *CorednsPluginsCi) BuildCoredns(ctx context.Context, source *dagger.Directory, corednsVersion string) (*dagger.File, error) {
	tag := "v" + corednsVersion

	ctr := m.buildBase().
		WithExec([]string{"git", "clone", "--branch", tag, "--depth", "1",
			"https://github.com/coredns/coredns.git", "/coredns"}).
		WithWorkdir("/coredns")

	// Copy (not bind-mount) each known plugin's vendored source into the
	// CoreDNS tree and patch plugin.cfg + go.mod to pull it in -- see
	// goBase's doc comment for why this must be WithDirectory, not
	// WithMountedDirectory: this is the exact layer whose content ends up
	// compiled into the shipped binary, so it's the highest-stakes place in
	// this file for BuildKit's mount-caching carve-out to silently serve
	// stale plugin source. Order doesn't matter across plugins (each patch
	// only touches its own line), but every patch must land before `go
	// generate`.
	//
	// External (third-party) plugins have no vendored source and no replace
	// directive: they are resolved with `go get`, which must run AFTER go
	// generate (see the ordering note below it), so they are collected here
	// and executed there.
	var externalGets []string

	for pluginDir, p := range pluginCfgPatches {
		switch {
		case p.replaceStockLine != "":
			ctr = ctr.WithExec([]string{"sed", "-i",
				fmt.Sprintf("s#^%s$#%s#", p.replaceStockLine, p.cfgLine),
				"plugin.cfg"})
		case p.insertAfterLine != "":
			ctr = ctr.WithExec([]string{"sed", "-i",
				fmt.Sprintf("/^%s$/a %s", p.insertAfterLine, p.cfgLine),
				"plugin.cfg"})
		default:
			return nil, fmt.Errorf("BuildCoredns: plugin %q has neither replaceStockLine nor insertAfterLine", pluginDir)
		}

		if p.externalModule != "" {
			if p.externalVersion == "" {
				return nil, fmt.Errorf("BuildCoredns: external plugin %q has externalModule %q but no externalVersion — refusing to build against a floating dependency", pluginDir, p.externalModule)
			}
			externalGets = append(externalGets,
				fmt.Sprintf("%s@%s", p.externalModule, p.externalVersion))
			continue
		}

		vendoredPath := fmt.Sprintf("/vendored/%s", pluginDir)
		ctr = ctr.
			WithDirectory(vendoredPath, source.Directory(pluginDir)).
			WithExec([]string{"go", "mod", "edit",
				"-replace", fmt.Sprintf("%s=%s", p.modulePath, vendoredPath)})
	}

	// go generate MUST run before go mod tidy: it regenerates zplugin.go,
	// which is what actually contains the import statements for the plugin
	// packages named in the go.mod replace directives above. Tidying first
	// (the original ordering here) sees no source yet importing those
	// modules and correctly-per-its-own-logic strips the replace as unused
	// ("provides package ... and is replaced but not required") — this was a
	// real bug, caught by the first live CI run once ARC could finally
	// schedule one.
	ctr = ctr.WithExec([]string{"go", "generate"})

	// Third-party plugins are fetched here, after go generate, for the same
	// reason the replace directives above have to survive it: until zplugin.go
	// imports the package, `go mod tidy` would drop the requirement as unused.
	// Sorted so the layer sequence is identical across runs — map iteration
	// order is randomized, and an unstable command order would needlessly
	// invalidate the build cache (and make two builds of one commit differ in
	// shape, which this file goes to some lengths to avoid elsewhere).
	sort.Strings(externalGets)
	for _, spec := range externalGets {
		ctr = ctr.WithExec([]string{"go", "get", spec})
	}

	ctr = ctr.
		// Force these past their CoreDNS-1.14.6-pinned versions explicitly:
		// grype found real High CVEs in the built binary (GO-2026-5970 /
		// x/text, GHSA-hrxh-6v49-42gf / grpc) even though the radnr/sni_tls
		// go.mod files here already require newer ones — `go mod tidy`
		// alone wasn't reliably picking the higher version across the
		// merged CoreDNS+plugin module graph, so pin the floor directly
		// rather than depend on MVS resolving it the way we expect.
		WithExec([]string{"go", "get", "golang.org/x/text@v0.39.0", "google.golang.org/grpc@v1.82.1"}).
		WithExec([]string{"go", "mod", "tidy"}).
		WithExec([]string{"go", "build", "-o", "/coredns-out/coredns", "."}).
		// radnr needs a raw ICMPv6 socket (CAP_NET_RAW) to send Router
		// Advertisements, and binding <1024 (CAP_NET_BIND_SERVICE) is needed
		// by any deployment of this image that serves real DNS on :53/:853/
		// :443 as the nonroot user it runs as. Kubernetes/containerd only
		// populate a container's Bounding capability set from
		// securityContext.capabilities.add -- NOT the Ambient set a nonroot
		// process needs for an added capability to survive its own execve
		// (confirmed live: CapBnd had NET_RAW, CapEff/CapAmb did not,
		// "operation not permitted" on the raw socket; the stale comment
		// below this function once claimed PodSecurityContext alone was
		// sufficient for CAP_NET_BIND_SERVICE too -- it isn't, same gap).
		// File capabilities sidestep this entirely: pP' = file_permitted &
		// bounding_set at exec time, independent of the pre-exec process'
		// ambient/effective state -- this is the textbook mechanism for
		// "let this one binary use a capability regardless of who runs it,"
		// and it's exactly this repo's multi-stage-build shape (COPY a
		// setcap'd binary into a distroless final stage is a common,
		// well-supported pattern). securityContext.capabilities.add must
		// still include both capabilities too (that's the bounding-set half
		// of the intersection above) -- setcap alone is not sufficient.
		WithExec([]string{"setcap", "cap_net_raw,cap_net_bind_service+ep", "/coredns-out/coredns"})

	// Fail the build here, immediately, if setcap silently no-op'd (e.g. a
	// build sandbox lacking CAP_SETFCAP itself) rather than discovering it
	// only after a full push+deploy cycle -- distroless has no getcap to
	// check this from inside the final runtime image, so this is the only
	// point this repo's pipeline can verify it at all.
	capOut, err := ctr.WithExec([]string{"getcap", "/coredns-out/coredns"}).Stdout(ctx)
	if err != nil {
		return nil, fmt.Errorf("BuildCoredns: getcap failed: %w", err)
	}
	for _, want := range []string{"cap_net_raw", "cap_net_bind_service"} {
		if !strings.Contains(capOut, want) {
			return nil, fmt.Errorf("BuildCoredns: setcap did not stick -- getcap shows %q, expected %s", capOut, want)
		}
	}

	return ctr.File("/coredns-out/coredns"), nil
}

// runtimeBase is the distroless base image the built coredns binary runs in,
// matching upstream CoreDNS's own Dockerfile choice
// (gcr.io/distroless/static-debian12:nonroot) — has /etc/ssl/certs bundled
// (needed for the forward plugin's DoT upstreams) and no shell/package
// manager.
//
// TODO: pin this to a digest (gcr.io/distroless/static-debian12:nonroot@sha256:...)
// once this is run somewhere with registry access to resolve one — a fabricated
// digest is worse than a floating tag (silent wrong-image pull or a build that
// never resolves). Get the real digest via `crane digest` or `docker buildx
// imagetools inspect` against this exact tag at build time, then replace this
// constant. Until pinned, this floats like image.nix's Nix input would without
// a lockfile — same reproducibility gap, tracked here instead of hidden.
const runtimeBaseRef = "gcr.io/distroless/static-debian12:nonroot"

// coredns needs CAP_NET_BIND_SERVICE to bind port 53 as the nonroot user this
// image runs as. BuildCoredns's setcap step (above) grants this at the file
// level, matching upstream's Dockerfile approach (setcap in a builder stage —
// distroless has no shell/setcap of its own to do this here directly).
//
// Every deployment of this image must ALSO add both capabilities via
// securityContext, even one that never touches a raw socket: setcap alone is
// not sufficient (the bounding set gates what a file capability can actually
// grant at exec time), and Kubernetes/containerd do not populate a nonroot
// container's Ambient set from securityContext.capabilities.add on their own
// (confirmed live) -- the file capability is what actually lets the grant
// survive execve, not the securityContext entry by itself. Both are required
// together:
//
//	securityContext:
//	  capabilities:
//	    add: ["NET_RAW", "NET_BIND_SERVICE"]
//
// Omitting either half reproduces one of two failures already hit live:
// "exec ...: operation not permitted" (missing from securityContext, so the
// bounding set doesn't contain what the file wants to grant) or an EPERM at
// bind()/socket() time (present in securityContext but the binary itself
// never had the file capability, back before this setcap step existed).

// Containerize packages a built coredns binary (from BuildCoredns) into a
// minimal runtime image and returns it as an OCI tarball (Container.AsTarball)
// — not pushed to a registry. See the package doc comment for why the push
// step is deliberately outside this function (mTLS client-cert auth to the registry,
// which Dagger's native registry auth doesn't support).
//
// Before returning, this runs `/coredns -plugins` inside the actual runtime
// container and checks every plugin in pluginCfgPatches shows up in its
// output. BuildCoredns compiling successfully does NOT mean the binary can
// run in this base image: golang:1.26 defaults cgo on, which produces a
// dynamically-linked binary that fails to exec at all
// (`exec /coredns: no such file or directory`) against distroless/static's
// total absence of libc. That broke silently all the way through build, tar,
// SBOM, and push in coredns-radnr's first live deploy — the container
// started and immediately CrashLoopBackOff'd. Running the binary here, in
// the exact image that ships, is the only check that would have caught it.
func (m *CorednsPluginsCi) Containerize(ctx context.Context, source *dagger.Directory, corednsVersion string) (*dagger.File, error) {
	binary, err := m.BuildCoredns(ctx, source, corednsVersion)
	if err != nil {
		return nil, err
	}

	ctr := dag.Container().
		From(runtimeBaseRef).
		WithFile("/coredns", binary).
		WithUser("nonroot:nonroot").
		WithWorkdir("/").
		WithExposedPort(53).
		WithExposedPort(853). // DoT
		WithExposedPort(443)  // DoH/DoH3

	// -plugins prints the compiled-in plugin list and exits 0 — no network,
	// no listeners, no config file needed. Runs BEFORE WithEntrypoint so
	// WithExec invokes /coredns directly rather than appending args to it.
	out, err := ctr.WithExec([]string{"/coredns", "-plugins"}).Stdout(ctx)
	if err != nil {
		return nil, fmt.Errorf("Containerize: smoke test failed to exec /coredns in %s (likely a dynamically-linked binary against a libc-free base — check CGO_ENABLED): %w", runtimeBaseRef, err)
	}
	for pluginDir, p := range pluginCfgPatches {
		name := p.cfgLine[:strings.IndexByte(p.cfgLine, ':')]
		if !strings.Contains(out, name) {
			return nil, fmt.Errorf("Containerize: smoke test ran but %q (plugin dir %s) is missing from `/coredns -plugins` output:\n%s", name, pluginDir, out)
		}
	}

	return ctr.WithEntrypoint([]string{"/coredns"}).AsTarball(), nil
}
