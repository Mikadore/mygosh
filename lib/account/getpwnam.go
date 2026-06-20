//go:build linux || darwin || freebsd || openbsd || netbsd

package account

/*
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static long get_pw_buf_size() {
    long n = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (n < 1024) {
        // POSIX allows -1 when there is no definite limit.
        // 16 KiB is a common fallback. If less than a kB
		// we also just fall back to 16kB
        return 16384;
    }
    return n;
}
*/
import "C"
import (
	"unsafe"

	"github.com/rotisserie/eris"
)

var ErrNotFound = eris.New("user not found")

type passwd_t struct {
	pw_name   string
	pw_passwd string
	pw_uid    uint32
	pw_gid    uint32
	pw_gecos  string
	pw_dir    string
	pw_shell  string
}

func getpwnamR(name string) (*passwd_t, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	bufSize := C.get_pw_buf_size()
	for {
		buf := C.malloc(C.size_t(bufSize))
		if buf == nil {
			return nil, eris.Errorf("malloc failed")
		}

		var pwd C.struct_passwd
		var result *C.struct_passwd

		rc := C.getpwnam_r(
			cname,
			&pwd,
			(*C.char)(buf),
			C.size_t(bufSize),
			&result,
		)

		if rc == C.ERANGE {
			C.free(buf)
			bufSize *= 2
			if bufSize > 1<<20 {
				return nil, eris.Errorf("passwd entry too large")
			}
			continue
		}

		defer C.free(buf)

		if rc != 0 {
			return nil, eris.Errorf("getpwnam_r(%q): %s", name, C.GoString(C.strerror(rc)))
		}

		if result == nil {
			return nil, ErrNotFound
		}

		return &passwd_t{
			pw_name:   C.GoString(result.pw_name),
			pw_passwd: C.GoString(result.pw_passwd),
			pw_uid:    uint32(result.pw_uid),
			pw_gid:    uint32(result.pw_gid),
			pw_gecos:  C.GoString(result.pw_gecos),
			pw_dir:    C.GoString(result.pw_dir),
			pw_shell:  C.GoString(result.pw_shell),
		}, nil
	}
}
