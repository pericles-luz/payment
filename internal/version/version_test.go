package version

import (
	"runtime/debug"
	"testing"
)

// TestInfoFallbackNonEmptyVersion verifies that, regardless of whether ldflags
// were injected, Info().Version is never empty. Under `go test` the package
// vars are unset and ReadBuildInfo carries no vcs.revision, so this exercises
// the "dev" fallback branch.
func TestInfoFallbackNonEmptyVersion(t *testing.T) {
	got := Info()
	if got.Version == "" {
		t.Fatalf("Info().Version is empty; want a non-empty fallback")
	}
}

// TestInfoUsesLdflagValues verifies that injected (or set) package vars are
// reported verbatim by Info(), and that the JSON-facing struct carries them in
// the expected fields.
func TestInfoUsesLdflagValues(t *testing.T) {
	origV, origC, origB := Version, Commit, BuildAt
	t.Cleanup(func() { Version, Commit, BuildAt = origV, origC, origB })

	Version = "v1.2.3"
	Commit = "abc123def456"
	BuildAt = "2026-06-25T12:00:00Z"

	got := Info()
	if got.Version != "v1.2.3" {
		t.Errorf("Version = %q; want v1.2.3", got.Version)
	}
	if got.Commit != "abc123def456" {
		t.Errorf("Commit = %q; want abc123def456", got.Commit)
	}
	if got.BuiltAt != "2026-06-25T12:00:00Z" {
		t.Errorf("BuiltAt = %q; want 2026-06-25T12:00:00Z", got.BuiltAt)
	}
}

// TestInfoPartialLdflags verifies that when only some vars are injected, the
// set ones are preserved and Version still resolves to a non-empty value.
func TestInfoPartialLdflags(t *testing.T) {
	origV, origC, origB := Version, Commit, BuildAt
	t.Cleanup(func() { Version, Commit, BuildAt = origV, origC, origB })

	// Only Version injected; Commit/BuildAt fall back to build info (likely
	// empty under `go test`, which is acceptable — only Version must be set).
	Version = "v9.9.9"
	Commit = ""
	BuildAt = ""

	got := Info()
	if got.Version != "v9.9.9" {
		t.Errorf("Version = %q; want v9.9.9", got.Version)
	}
}

// TestResolve exercises every precedence branch of the pure resolver: ldflags
// win over VCS, VCS fills empties, and "dev"/empty defaults apply when both are
// absent.
func TestResolve(t *testing.T) {
	tests := []struct {
		name            string
		v, c, b, rev, t string
		want            Build
	}{
		{
			name: "ldflags fully set — VCS ignored",
			v:    "v1.0.0", c: "deadbeef", b: "2026-06-10T00:00:00Z",
			rev: "ignored", t: "ignored",
			want: Build{Version: "v1.0.0", Commit: "deadbeef", BuiltAt: "2026-06-10T00:00:00Z"},
		},
		{
			name: "no ldflags, VCS present — VCS fills all, Version=rev",
			rev:  "cafef00d", t: "2026-01-02T03:04:05Z",
			want: Build{Version: "cafef00d", Commit: "cafef00d", BuiltAt: "2026-01-02T03:04:05Z"},
		},
		{
			name: "nothing at all — dev fallback, empty commit/built_at",
			want: Build{Version: "dev", Commit: "", BuiltAt: ""},
		},
		{
			name: "version via ldflags, commit/time via VCS",
			v:    "v2.3.4", rev: "abc123", t: "2026-02-02T02:02:02Z",
			want: Build{Version: "v2.3.4", Commit: "abc123", BuiltAt: "2026-02-02T02:02:02Z"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolve(tc.v, tc.c, tc.b, tc.rev, tc.t)
			if got != tc.want {
				t.Errorf("resolve = %+v; want %+v", got, tc.want)
			}
		})
	}
}

// TestBuildInfoVCS verifies the accessor runs without panicking and returns
// consistent (possibly empty) strings under the test binary. It documents that
// empty results are acceptable — the resolver layers the "dev" default on top.
func TestBuildInfoVCS(t *testing.T) {
	rev, ts := buildInfoVCS()
	// Under `go test` vcs stamping is usually absent; both empty is valid.
	// We only assert the call is total (no panic) and returns strings.
	_ = rev
	_ = ts
}

// TestParseVCSSettings exercises the pure settings scanner with fabricated
// build settings, covering the vcs.revision / vcs.time cases and the
// unknown-key skip that the test binary's own settings can't guarantee.
func TestParseVCSSettings(t *testing.T) {
	rev, ts := parseVCSSettings([]debug.BuildSetting{
		{Key: "GOARCH", Value: "amd64"}, // ignored key
		{Key: "vcs.revision", Value: "feedface"},
		{Key: "vcs.time", Value: "2026-03-03T03:03:03Z"},
		{Key: "vcs.modified", Value: "false"}, // ignored key
	})
	if rev != "feedface" {
		t.Errorf("revision = %q; want feedface", rev)
	}
	if ts != "2026-03-03T03:03:03Z" {
		t.Errorf("buildTime = %q; want 2026-03-03T03:03:03Z", ts)
	}

	// Empty settings → empty results.
	rev, ts = parseVCSSettings(nil)
	if rev != "" || ts != "" {
		t.Errorf("parseVCSSettings(nil) = (%q, %q); want empty", rev, ts)
	}
}
