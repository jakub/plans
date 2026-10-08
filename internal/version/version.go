// Package version exposes build metadata injected at link time.
package version

import "fmt"

var (
	// Version is the semantic version or development identifier.
	Version = "dev"
	// Commit is the source revision used for the build.
	Commit = "unknown"
	// Date is the UTC build timestamp.
	Date = "unknown"
)

// String returns a human-readable build identifier.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, Date)
}
