// Package buildinfo holds build metadata injected at link time:
//
//	go build -ldflags "-X github.com/ilushka-off/GophKeeper/internal/buildinfo.Version=v1.0.0 ..."
package buildinfo

import "fmt"

// Build metadata. The values are overwritten with -ldflags -X.
var (
	// Version is the release version.
	Version = "N/A"
	// Date is the build date.
	Date = "N/A"
	// Commit is the git commit the binary was built from.
	Commit = "N/A"
)

// String returns build metadata in a human readable form.
func String() string {
	return fmt.Sprintf("Version: %s\nBuild date: %s\nCommit: %s", Version, Date, Commit)
}
