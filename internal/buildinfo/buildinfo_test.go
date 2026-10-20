package buildinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestString(t *testing.T) {
	v, d, c := Version, Date, Commit
	t.Cleanup(func() { Version, Date, Commit = v, d, c })

	assert.Equal(t, "Version: N/A\nBuild date: N/A\nCommit: N/A", String())

	Version, Date, Commit = "v1.0.0", "2026-10-20", "abc123"
	assert.Equal(t, "Version: v1.0.0\nBuild date: 2026-10-20\nCommit: abc123", String())
}
