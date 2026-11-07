module github.com/puredevotion/coredns-plugins/zoneversion

go 1.27.0

toolchain go1.27.3

require (
	github.com/coredns/caddy v1.1.4
	github.com/coredns/coredns v1.15.0
	github.com/miekg/dns v1.1.73
	github.com/prometheus/client_golang v1.25.0
	github.com/prometheus/client_model v0.6.3
)

require (
	github.com/apparentlymart/go-cidr v1.1.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/flynn/go-shlex v0.0.0-20150515145356-3f9db97f8568 // indirect
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20180507213350-8e809c8a8645 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.64.1 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/grpc v1.84.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// Upstream miekg/dns v1.1.73 cannot unpack the empty ZONEVERSION option of a
// conformant RFC 9660 query (the server answers FORMERR before any plugin
// runs). Our fork adds EDNS0_ZONEVERSION.Empty; see
// docs/zoneversion-plugin.md, "The miekg/dns fork". Keep in step with
// miekgDNSForkReplace in ci/main.go.
replace github.com/miekg/dns => github.com/puredevotion/dns v1.1.73-pd.1
