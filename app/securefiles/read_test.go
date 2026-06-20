package securefiles

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadEnforcesModeSizeSymlinkAndMissingPolicies(t *testing.T) {
	owner := uint32(os.Geteuid())

	t.Run("reads nested file", func(t *testing.T) {
		anchor := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(anchor, "nested"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(anchor, "nested", "file"), []byte("contents"), 0o644))
		got, err := Read(anchor, "nested/file", Policy{OwnerID: owner, MaxSize: 8, AllowGlobalRead: true})
		require.NoError(t, err)
		require.Equal(t, []byte("contents"), got)
	})

	t.Run("global read", func(t *testing.T) {
		anchor := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(anchor, "file"), []byte("secret"), 0o644))
		_, err := Read(anchor, "file", Policy{OwnerID: owner, MaxSize: 16})
		require.ErrorContains(t, err, "read permission")
	})

	t.Run("group write", func(t *testing.T) {
		anchor := t.TempDir()
		path := filepath.Join(anchor, "file")
		require.NoError(t, os.WriteFile(path, []byte("trust"), 0o600))
		require.NoError(t, os.Chmod(path, 0o620))
		_, err := Read(anchor, "file", Policy{OwnerID: owner, MaxSize: 16, AllowGlobalRead: true})
		require.ErrorContains(t, err, "write permission")
	})

	t.Run("size", func(t *testing.T) {
		anchor := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(anchor, "file"), []byte("too large"), 0o600))
		_, err := Read(anchor, "file", Policy{OwnerID: owner, MaxSize: 3})
		require.ErrorContains(t, err, "exceeds maximum")
	})

	t.Run("symlink", func(t *testing.T) {
		anchor := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(anchor, "target"), []byte("secret"), 0o600))
		require.NoError(t, os.Symlink("target", filepath.Join(anchor, "link")))
		_, err := Read(anchor, "link", Policy{OwnerID: owner, MaxSize: 16})
		require.Error(t, err)
	})

	t.Run("missing", func(t *testing.T) {
		_, err := Read(t.TempDir(), "missing", Policy{OwnerID: owner, MaxSize: 16})
		require.True(t, errors.Is(err, os.ErrNotExist))
	})
}
