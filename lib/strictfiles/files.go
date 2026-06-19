// ALWAYS USE `O_CLOEXEC` FOR ANY OPENED FILE
package strictfiles

import (
	"os"

	"golang.org/x/sys/unix"
)

type CheckedFile struct {
	fd int
	st unix.Stat_t
}

type CheckOptions struct {
	// Must use O_DIRECTORY 
	WantDir bool
	// Checks the file's ownership (files owned by root are valid too)
	OwnerID uint32
	// Sets O_NOFOLLOW or OpenHow, false by default
	AllowSymlinks bool
	// Accept read permissions for 'group' and 'other'
	AllowGlobalRead bool
	// Maximum accepted file size, 0 means size is not checked
	MaxSize uint64
}

// Primitive wrapper for `Open` used by other functions in the package
// accepts extra `oflags` to set for mode, and appends any mode flags
// that follow from the `CheckOptions`. `perm` is passed as-is.
// After opening it stats the file descriptor, and checks the results
// according to `CheckOptions`
func openChecked(path string, oflags int, perm int, opt CheckOptions) (CheckedFile, error) {
	mode := oflags
	if !opt.AllowSymlinks {
		mode |= unix.O_NOFOLLOW
	}
	if ... {

	}
	fd, err := unix.Open(path, unix.O_CLOEXEC, perm)
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	// checks
	return CheckedFile{fd: fd, st: st}, nil
}

// Uses `O_PATH` + `O_DIRECTORY`, symlinks are allowed
func OpenDir(path string) (CheckedFile, error) {}

// Uses openat to perform a checked open relative to the checked Anchor directory,
// symlinks forbidden
func (cf *CheckedFile) OpenAt(name string, opt CheckOptions) {}

// converts to `os.File`
func (cf *CheckedFile) ToFile() *os.File {}


