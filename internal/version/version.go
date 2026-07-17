// Package version holds build identity, injected at link time via -ldflags.
package version

import "runtime/debug"

// These are overridden with -ldflags "-X .../version.Version=v1.2.3 ...".
var (
	Version = "dev"     // semantic version of this build
	Commit  = "unknown" // git commit
	Date    = "unknown" // build date (RFC3339)
)

// String returns a compact human-readable build identity.
func String() string {
	v := Version
	if v == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
	}
	return v + " (" + Commit + ", " + Date + ")"
}
