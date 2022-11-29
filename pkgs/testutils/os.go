package testutils

import (
	"os"
	"testing"

	"github.com/jaekwon/testify/require"
)

// NewTestCaseDir creates a new temporary directory for a test case.
// Returns the directory path and a cleanup function.
// nolint: errcheck
func NewTestCaseDir(t *testing.T) (string, func()) {
	dir, err := os.MkdirTemp("", t.Name()+"_")
	require.NoError(t, err)
	return dir, func() { os.RemoveAll(dir) }
}
