package strictfiles

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestOpenCheckedReadsRegularFileAndSetsCloseOnExec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0o600))

	checked, err := openChecked(path, unix.O_RDONLY, 0, CheckOptions{
		OwnerID: uint32(os.Geteuid()),
		MaxSize: 6,
	})
	require.NoError(t, err)

	fdFlags, err := unix.FcntlInt(uintptr(checked.fd), unix.F_GETFD, 0)
	require.NoError(t, err)
	require.NotZero(t, fdFlags&unix.FD_CLOEXEC)

	file := checked.ToFile()
	require.NotNil(t, file)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	require.Nil(t, checked.ToFile())

	got, err := io.ReadAll(file)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestOpenCheckedRejectsUnexpectedMetadata(t *testing.T) {
	uid := uint32(os.Geteuid())

	t.Run("directory when file wanted", func(t *testing.T) {
		_, err := openChecked(t.TempDir(), unix.O_RDONLY, 0, CheckOptions{
			OwnerID: uid,
		})
		require.ErrorContains(t, err, "expected regular file")
	})

	t.Run("file when directory wanted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(path, nil, 0o600))

		_, err := openChecked(path, unix.O_RDONLY, 0, CheckOptions{
			WantDir: true,
			OwnerID: uid,
		})
		require.Error(t, err)
	})

	t.Run("global read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(path, nil, 0o644))

		_, err := openChecked(path, unix.O_RDONLY, 0, CheckOptions{
			OwnerID: uid,
		})
		require.ErrorContains(t, err, "read permission")

		checked, err := openChecked(path, unix.O_RDONLY, 0, CheckOptions{
			OwnerID:         uid,
			AllowGlobalRead: true,
		})
		require.NoError(t, err)
		require.NoError(t, checked.Close())
	})

	t.Run("global write", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		require.NoError(t, os.Chmod(path, 0o620))

		_, err := openChecked(path, unix.O_RDONLY, 0, CheckOptions{
			OwnerID:         uid,
			AllowGlobalRead: true,
		})
		require.ErrorContains(t, err, "write permission")
	})

	t.Run("maximum size", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(path, []byte("too large"), 0o600))

		_, err := openChecked(path, unix.O_RDONLY, 0, CheckOptions{
			OwnerID: uid,
			MaxSize: 3,
		})
		require.ErrorContains(t, err, "exceeds maximum")
	})
}

func TestOpenCheckedRejectsWrongOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, nil, 0o600))

	var st unix.Stat_t
	require.NoError(t, unix.Stat(path, &st))

	if st.Uid == 0 {
		require.NoError(t, unix.Chown(path, 1, -1))
		st.Uid = 1
		t.Cleanup(func() { _ = unix.Chown(path, 0, -1) })
	}

	_, err := openChecked(path, unix.O_RDONLY, 0, CheckOptions{
		OwnerID: st.Uid + 1,
	})
	require.ErrorContains(t, err, "owner uid")
}

func TestOpenCheckedSymlinkPolicy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	require.NoError(t, os.WriteFile(target, nil, 0o600))
	require.NoError(t, os.Symlink("target", link))

	_, err := openChecked(link, unix.O_RDONLY, 0, CheckOptions{
		OwnerID: uint32(os.Geteuid()),
	})
	require.Error(t, err)

	checked, err := openChecked(link, unix.O_RDONLY, 0, CheckOptions{
		OwnerID:       uint32(os.Geteuid()),
		AllowSymlinks: true,
	})
	require.NoError(t, err)
	require.NoError(t, checked.Close())
}

func TestOpenDirAndOpenAt(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "keys"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "keys", "id"), []byte("key"), 0o600))

	anchor, err := OpenDir(root)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, anchor.Close()) })

	checked, err := anchor.OpenAt("keys/id", CheckOptions{
		OwnerID: uint32(os.Geteuid()),
		MaxSize: 3,
	})
	require.NoError(t, err)

	file := checked.ToFile()
	require.NotNil(t, file)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	got, err := io.ReadAll(file)
	require.NoError(t, err)
	require.Equal(t, []byte("key"), got)
}

func TestOpenDirAllowsSymlinkToTrustedDirectory(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	link := filepath.Join(parent, "link")
	require.NoError(t, os.Symlink("target", link))

	anchor, err := OpenDir(link)
	require.NoError(t, err)
	require.NoError(t, anchor.Close())
}

func TestOpenAtRejectsSymlinksAndEscapes(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	require.NoError(t, os.Mkdir(root, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(parent, "outside"), []byte("outside"), 0o600))
	require.NoError(t, os.Symlink("../outside", filepath.Join(root, "link")))
	require.NoError(t, os.Mkdir(filepath.Join(root, "nested"), 0o700))
	require.NoError(t, os.Symlink("nested", filepath.Join(root, "nested-link")))

	anchor, err := OpenDir(root)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, anchor.Close()) })

	options := CheckOptions{OwnerID: uint32(os.Geteuid())}

	_, err = anchor.OpenAt("link", options)
	require.Error(t, err)

	_, err = anchor.OpenAt("nested-link/file", options)
	require.Error(t, err)

	_, err = anchor.OpenAt("../outside", options)
	require.Error(t, err)

	_, err = anchor.OpenAt("/etc/passwd", options)
	require.Error(t, err)

	options.AllowSymlinks = true
	_, err = anchor.OpenAt("link", options)
	require.ErrorContains(t, err, "does not allow symlinks")
}

func TestClosedCheckedFileCannotBeReused(t *testing.T) {
	anchor, err := OpenDir(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, anchor.Close())
	require.NoError(t, anchor.Close())

	_, err = anchor.OpenAt("file", CheckOptions{})
	require.ErrorContains(t, err, "closed directory")
	require.Nil(t, anchor.ToFile())
}

func TestZeroCheckedFileIsClosed(t *testing.T) {
	var checked CheckedFile

	require.NoError(t, checked.Close())
	require.Nil(t, checked.ToFile())
	_, err := checked.OpenAt("file", CheckOptions{})
	require.ErrorContains(t, err, "closed directory")
}

func TestOpenAtNoSymlinksFallback(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "nested"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "nested", "file"), nil, 0o600))
	require.NoError(t, os.Symlink("nested", filepath.Join(root, "link")))

	dirfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unix.Close(dirfd)) })

	fd, err := openAtNoSymlinks(
		dirfd,
		"nested/file",
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
	)
	require.NoError(t, err)
	require.NoError(t, unix.Close(fd))

	_, err = openAtNoSymlinks(
		dirfd,
		"link/file",
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
	)
	require.Error(t, err)

	_, err = openAtNoSymlinks(
		dirfd,
		"../outside",
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
	)
	require.True(t, errors.Is(err, unix.EXDEV))
}
