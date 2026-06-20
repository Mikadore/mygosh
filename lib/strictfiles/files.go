package strictfiles

import (
	"errors"
	"os"
	"strings"

	"github.com/rotisserie/eris"
	"golang.org/x/sys/unix"
)

const invalidFD = -1

// CheckedFile is an open file descriptor whose metadata has been checked.
//
// A CheckedFile owns its descriptor. Call Close, or transfer ownership to an
// *os.File with ToFile. CheckedFile values must not be copied after use.
type CheckedFile struct {
	fd   int
	name string
	open bool
	st   unix.Stat_t
}

type CheckOptions struct {
	// WantDir requires the opened path to be a directory. Otherwise it must be
	// a regular file.
	WantDir bool
	// OwnerID is the expected owner. Files owned by root are accepted too.
	OwnerID uint32
	// AllowSymlinks permits the final path component to be a symlink for direct
	// opens. OpenAt always forbids symlinks.
	AllowSymlinks bool
	// AllowGlobalRead accepts group and other read permissions. Group and other
	// write permissions are never accepted.
	AllowGlobalRead bool
	// MaxSize is the maximum accepted file size. Zero disables the size check.
	MaxSize uint64
}

// openChecked opens path, then checks metadata from the open descriptor.
// O_CLOEXEC and O_NONBLOCK are always added. O_NONBLOCK prevents a path that
// resolves to a FIFO from blocking before its type can be rejected.
func openChecked(path string, oflags int, perm int, opt CheckOptions) (CheckedFile, error) {
	flags := oflags | unix.O_CLOEXEC | unix.O_NONBLOCK
	if opt.WantDir {
		flags |= unix.O_DIRECTORY
	}
	if !opt.AllowSymlinks {
		flags |= unix.O_NOFOLLOW
	}

	fd, err := unix.Open(path, flags, uint32(perm))
	if err != nil {
		return CheckedFile{}, eris.Wrapf(err, "open %q", path)
	}

	return checkOpened(fd, path, opt)
}

func checkOpened(fd int, name string, opt CheckOptions) (CheckedFile, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return CheckedFile{}, eris.Wrapf(err, "stat opened file %q", name)
	}

	if err := checkStat(st, opt); err != nil {
		_ = unix.Close(fd)
		return CheckedFile{}, eris.Wrapf(err, "check opened file %q", name)
	}

	return CheckedFile{fd: fd, name: name, open: true, st: st}, nil
}

func checkStat(st unix.Stat_t, opt CheckOptions) error {
	fileType := st.Mode & unix.S_IFMT
	if opt.WantDir {
		if fileType != unix.S_IFDIR {
			return eris.Errorf("expected directory, got mode %#o", st.Mode)
		}
	} else if fileType != unix.S_IFREG {
		return eris.Errorf("expected regular file, got mode %#o", st.Mode)
	}

	if st.Uid != 0 && st.Uid != opt.OwnerID {
		return eris.Errorf("owner uid %d is neither root nor expected uid %d", st.Uid, opt.OwnerID)
	}

	if st.Mode&(unix.S_IWGRP|unix.S_IWOTH) != 0 {
		return eris.Errorf("group or other write permission is set: mode %#o", st.Mode)
	}
	if !opt.AllowGlobalRead && st.Mode&(unix.S_IRGRP|unix.S_IROTH) != 0 {
		return eris.Errorf("group or other read permission is set: mode %#o", st.Mode)
	}

	if opt.MaxSize != 0 && (st.Size < 0 || uint64(st.Size) > opt.MaxSize) {
		return eris.Errorf("size %d exceeds maximum %d", st.Size, opt.MaxSize)
	}

	return nil
}

// OpenDir opens a trusted directory anchor. The directory may be reached
// through symlinks, but the opened directory itself must be owned by the
// effective user or root and must not be writable by group or other.
func OpenDir(path string) (CheckedFile, error) {
	return OpenDirWithOptions(path, CheckOptions{
		WantDir:         true,
		OwnerID:         uint32(unix.Geteuid()),
		AllowSymlinks:   true,
		AllowGlobalRead: true,
	})
}

// OpenDirWithOptions opens a caller-selected directory anchor and validates
// it with caller-owned ownership and mode policy.
func OpenDirWithOptions(path string, opt CheckOptions) (CheckedFile, error) {
	opt.WantDir = true
	return openChecked(path, unix.O_PATH, 0, opt)
}

// OpenFile opens and validates a regular file directly. Callers handling
// credential or trust paths should normally prefer an anchored OpenAt.
func OpenFile(path string, opt CheckOptions) (CheckedFile, error) {
	opt.WantDir = false
	return openChecked(path, unix.O_RDONLY, 0, opt)
}

// OpenAt opens a regular file read-only beneath the checked directory anchor.
// Symlinks are forbidden in every path component, and the path may not escape
// the anchor.
func (cf *CheckedFile) OpenAt(name string, opt CheckOptions) (CheckedFile, error) {
	if cf == nil || !cf.open {
		return CheckedFile{}, eris.New("open relative to closed directory")
	}
	if cf.st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return CheckedFile{}, eris.New("open relative to non-directory")
	}
	if opt.AllowSymlinks {
		return CheckedFile{}, eris.New("OpenAt does not allow symlinks")
	}

	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW
	if opt.WantDir {
		flags |= unix.O_DIRECTORY
	}

	how := &unix.OpenHow{
		Flags: uint64(flags),
		Resolve: unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(cf.fd, name, how)
	if errors.Is(err, unix.ENOSYS) {
		fd, err = openAtNoSymlinks(cf.fd, name, flags)
	}
	if err != nil {
		return CheckedFile{}, eris.Wrapf(err, "open %q beneath %q", name, cf.name)
	}

	return checkOpened(fd, name, opt)
}

// openAtNoSymlinks is the secure fallback for kernels without openat2. Each
// intermediate directory is opened and pinned before the next component is
// resolved.
func openAtNoSymlinks(dirfd int, name string, flags int) (int, error) {
	if name == "" || strings.HasPrefix(name, "/") {
		return invalidFD, unix.EINVAL
	}

	components := strings.Split(name, "/")
	currentFD := dirfd
	ownsCurrent := false
	defer func() {
		if ownsCurrent {
			_ = unix.Close(currentFD)
		}
	}()

	var pathComponents []string
	for _, component := range components {
		switch component {
		case "", ".":
			continue
		case "..":
			return invalidFD, unix.EXDEV
		default:
			pathComponents = append(pathComponents, component)
		}
	}

	if len(pathComponents) == 0 {
		return unix.Openat(currentFD, ".", flags, 0)
	}

	for _, component := range pathComponents[:len(pathComponents)-1] {
		nextFD, err := unix.Openat(
			currentFD,
			component,
			unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return invalidFD, err
		}
		if ownsCurrent {
			_ = unix.Close(currentFD)
		}
		currentFD = nextFD
		ownsCurrent = true
	}

	return unix.Openat(currentFD, pathComponents[len(pathComponents)-1], flags, 0)
}

// Close closes the owned descriptor. It is safe to call more than once.
func (cf *CheckedFile) Close() error {
	if cf == nil || !cf.open {
		return nil
	}

	fd := cf.fd
	cf.open = false
	cf.fd = invalidFD
	if err := unix.Close(fd); err != nil {
		return eris.Wrapf(err, "close %q", cf.name)
	}
	return nil
}

// ToFile transfers descriptor ownership to an *os.File. It returns nil if the
// descriptor was already closed or transferred.
func (cf *CheckedFile) ToFile() *os.File {
	if cf == nil || !cf.open {
		return nil
	}

	fd := cf.fd
	cf.open = false
	cf.fd = invalidFD
	return os.NewFile(uintptr(fd), cf.name)
}
