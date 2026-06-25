// Package version exposes the build provenance (version tag, commit SHA, and
// build timestamp) of the running binary as a single Build struct.
//
// The three package vars below are intended to be injected at build time via
// linker flags, e.g.:
//
//	go build -ldflags "\
//	  -X github.com/ia-dev-sindireceita/payment/internal/version.Version=v1.2.3 \
//	  -X github.com/ia-dev-sindireceita/payment/internal/version.Commit=$(git rev-parse HEAD) \
//	  -X github.com/ia-dev-sindireceita/payment/internal/version.BuildAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// When the flags are absent (a plain `go build` or `go run`, e.g. local dev or
// the test binary) Info() falls back to runtime/debug.ReadBuildInfo() so the
// /healthz route still answers 200 with a meaningful payload. The package is the
// single source of build provenance for the api binary (hexagonal lens: the HTTP
// adapter depends on this leaf, not on scattered globals), and carries no
// secrets, so it is safe to surface on the unauthenticated health check.
package version

import "runtime/debug"

// These vars are overridden at link time with `-ldflags -X`. They are
// deliberately plain strings (not consts) so the linker can rewrite them. Do
// NOT read them directly from handlers — call Info(), which layers the
// build-info fallback on top.
var (
	// Version is the release tag or short SHA (e.g. `git describe --tags --always`).
	Version string
	// Commit is the full git commit SHA.
	Commit string
	// BuildAt is the build timestamp in RFC3339 (UTC).
	BuildAt string
)

// Build is the build provenance reported by /healthz. It carries no secrets —
// only version, commit, and build time — and is safe to expose on an
// unauthenticated endpoint.
type Build struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
}

// Info returns the build provenance, preferring ldflags-injected values and
// falling back to runtime/debug.ReadBuildInfo() (vcs.revision / vcs.time) when
// they are absent. Any field still empty after both sources defaults to "dev"
// (Version) or "" (Commit / BuiltAt), guaranteeing a non-empty Version so the
// route always answers with a valid payload.
func Info() Build {
	rev, t := buildInfoVCS()
	return resolve(Version, Commit, BuildAt, rev, t)
}

// resolve layers the VCS fallback (rev, t) on top of the ldflags-injected
// values (v, c, b) and applies the "dev" default. It is pure — no globals, no
// I/O — so every branch is exercised directly by the tests. Precedence:
// ldflags value wins; else VCS value; else "dev" for Version (Commit/BuiltAt
// stay empty rather than guessing).
func resolve(v, c, b, rev, t string) Build {
	if c == "" {
		c = rev
	}
	if b == "" {
		b = t
	}
	// Version has no direct ReadBuildInfo equivalent; use the revision when
	// available so a flagless build still reports something, else "dev".
	if v == "" {
		if rev != "" {
			v = rev
		} else {
			v = "dev"
		}
	}
	return Build{Version: v, Commit: c, BuiltAt: b}
}

// buildInfoVCS extracts vcs.revision and vcs.time from the embedded build info.
// Returns empty strings when build info is unavailable (e.g. `go test` without
// VCS stamping) — callers handle the empty case.
func buildInfoVCS() (revision, buildTime string) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "", ""
	}
	return parseVCSSettings(bi.Settings)
}

// parseVCSSettings is the pure half of buildInfoVCS: it scans build settings
// for vcs.revision / vcs.time. Split out so the scan logic is unit-testable
// without depending on whether the test binary itself was VCS-stamped.
func parseVCSSettings(settings []debug.BuildSetting) (revision, buildTime string) {
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			buildTime = s.Value
		}
	}
	return revision, buildTime
}
