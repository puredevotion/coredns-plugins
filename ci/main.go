// Package main is this repository's Dagger CI module: test each plugin
// standalone, build a custom CoreDNS binary with the plugin(s) wired in via
// plugin.cfg, and package the resulting image. The build step is CoreDNS-
// specific (clone pinned upstream source, patch plugin.cfg, go generate)
// rather than a plain `go build`.
//
// Usage (local or in CI, same commands, run from ci/):
//
//	dagger call test-plugin   --source=.. --plugin-dir=sni_tls
//	dagger call lint-plugin   --source=.. --plugin-dir=sni_tls
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
	"strings"

	"dagger/coredns-plugins-ci/internal/dagger"
)

// CorednsPluginsCi is the CI module root.
type CorednsPluginsCi struct{}

// plugins lists every plugin directory this module knows how to wire into a
// CoreDNS build, and where each replaces/inserts into plugin.cfg.
//
//   - sni_tls REPLACES the stock tls:tls line (same slot: it configures the
//     listener's TLS before any query-handling plugin runs, same as stock tls).
//   - radnr is listener-only (no ServeDNS, like health/metrics) so its slot in
//     the chain doesn't matter for query handling; placed next to health/ready
//     for locality with the other listener-only plugins.
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
}

// goBase returns a Go build container with the plugin source mounted and module
// cache wired to a persistent Dagger cache volume (shared across runs on the
// engine, same convention as ci/dagger/main.go's goBase).
func (m *CorednsPluginsCi) goBase(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From("golang:1.26").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("go-build")).
		WithMountedDirectory("/src", source).
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

// LintPlugin runs go vet on the plugin (baseline lint, matches ci/dagger's Lint).
// See TestPlugin's doc comment for the source-root path convention.
func (m *CorednsPluginsCi) LintPlugin(ctx context.Context, source *dagger.Directory, pluginDir string) (string, error) {
	return m.goBase(source).
		WithWorkdir("/src/" + pluginDir).
		WithExec([]string{"go", "vet", "./..."}).
		Stdout(ctx)
}

// buildBase returns a container with git+bash (needed for the clone + sed
// patch + go generate steps) and the Go module/build caches wired, matching
// goBase's cache convention.
func (m *CorednsPluginsCi) buildBase() *dagger.Container {
	return dag.Container().
		From("golang:1.26").
		// update+install combined in one step (not two, as a bare `apt-get
		// update` was before): this Dagger engine is long-lived
		// (kube-pod://dagger-engine-0, shared across CI runs), and a
		// separate `apt-get update` step reuses its OLD cached layer
		// whenever its own command text is unchanged, regardless of how
		// stale the index inside it is -- caught live when adding
		// libcap2-bin below to `install` alone didn't invalidate that
		// cache, and "Unable to locate package libcap2-bin" turned out to
		// mean a stale reused index, not a wrong package name. Combining
		// them means any change to what's installed also forces a fresh
		// update, every time.
		//
		// libcap2-bin: setcap, used after the build to grant cap_net_raw to
		// the binary itself (see BuildCoredns) so radnr's raw ICMPv6 socket
		// works for the nonroot user this image runs as.
		// -o Acquire::ForceIPv4=true: this build runs in a k8s pod on a
		// dual-stack CNI, and apt tried only deb.debian.org's AAAA records
		// (all four, all "Network is unreachable") with no IPv4 fallback --
		// caught live. Forcing IPv4 sidesteps whatever IPv6 egress gap
		// exists in this runner's network path.
		WithExec([]string{"sh", "-c", "apt-get -o Acquire::ForceIPv4=true update && apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends git libcap2-bin"}).
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
// wire in every plugin in this repo that the module knows about (see
// pluginCfgPatches), adds a go.mod replace directive per
// plugin pointing at its vendored source (mounted from `source`), runs `go
// generate` (regenerates zplugin.go/zdirectives.go per coredns.go's
// //go:generate directives), and builds the coredns binary. Returns the
// built binary as a File so Containerize can wrap it into a runtime image.
func (m *CorednsPluginsCi) BuildCoredns(ctx context.Context, source *dagger.Directory, corednsVersion string) (*dagger.File, error) {
	tag := "v" + corednsVersion

	ctr := m.buildBase().
		WithExec([]string{"git", "clone", "--branch", tag, "--depth", "1",
			"https://github.com/coredns/coredns.git", "/coredns"}).
		WithWorkdir("/coredns")

	// Mount each known plugin's vendored source into the CoreDNS tree and
	// patch plugin.cfg + go.mod to pull it in. Order doesn't matter across
	// plugins (each patch only touches its own line), but every patch must
	// land before `go generate`.
	for pluginDir, p := range pluginCfgPatches {
		vendoredPath := fmt.Sprintf("/vendored/%s", pluginDir)
		ctr = ctr.WithMountedDirectory(vendoredPath, source.Directory(pluginDir))

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

		ctr = ctr.WithExec([]string{"go", "mod", "edit",
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
	ctr = ctr.
		WithExec([]string{"go", "generate"}).
		WithExec([]string{"go", "mod", "tidy"}).
		WithExec([]string{"go", "build", "-o", "/coredns-out/coredns", "."}).
		// radnr needs a raw ICMPv6 socket (CAP_NET_RAW) to send Router
		// Advertisements. This image runs as a nonroot user, and Kubernetes/
		// containerd only populate a container's Bounding capability set
		// from securityContext.capabilities.add -- NOT the Ambient set a
		// nonroot process needs for an added capability to survive its own
		// execve (confirmed live: CapBnd had NET_RAW, CapEff/CapAmb did not,
		// "operation not permitted" on the raw socket). File capabilities
		// sidestep this entirely: pP' = file_permitted & bounding_set at
		// exec time, independent of the pre-exec process' ambient/effective
		// state -- this is the textbook mechanism for "let this one binary
		// use a capability regardless of who runs it," and it's exactly
		// this repo's multi-stage-build shape (COPY a setcap'd binary into
		// a distroless final stage is a common, well-supported pattern).
		// securityContext.capabilities.add still must include NET_RAW too
		// (it's the bounding-set half of the intersection above) -- this
		// setcap alone is not sufficient on its own.
		WithExec([]string{"setcap", "cap_net_raw+ep", "/coredns-out/coredns"})

	// Fail the build here, immediately, if setcap silently no-op'd (e.g. a
	// build sandbox lacking CAP_SETFCAP itself) rather than discovering it
	// only after a full push+deploy cycle -- distroless has no getcap to
	// check this from inside the final runtime image, so this is the only
	// point this repo's pipeline can verify it at all.
	capOut, err := ctr.WithExec([]string{"getcap", "/coredns-out/coredns"}).Stdout(ctx)
	if err != nil {
		return nil, fmt.Errorf("BuildCoredns: getcap failed: %w", err)
	}
	if !strings.Contains(capOut, "cap_net_raw") {
		return nil, fmt.Errorf("BuildCoredns: setcap did not stick -- getcap shows %q, expected cap_net_raw", capOut)
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
// image runs as (matches upstream's Dockerfile, which uses setcap in a builder
// stage — not available here since distroless has no shell/setcap binary).
// This image relies on the Kubernetes PodSecurityContext granting the
// capability at the container level instead:
//
//	securityContext:
//	  capabilities:
//	    add: ["NET_BIND_SERVICE"]
//
// Required wherever this image is deployed.

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
