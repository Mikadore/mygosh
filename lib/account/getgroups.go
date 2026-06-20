//go:build linux || darwin || freebsd || openbsd || netbsd

package account

/*
#include <errno.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static long get_gr_buf_size() {
	long n = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (n < 1024) {
		// POSIX allows -1 when there is no definite limit.
		// Use 16 KiB for an absent or implausibly small hint.
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

const (
	initialGroupCount = 16
	maxGroupCount     = 1 << 16
	maxGroupEntrySize = 1 << 20
)

func getgrgidR(gid GUID) (string, error) {
	bufSize := C.get_gr_buf_size()
	for {
		buf := C.malloc(C.size_t(bufSize))
		if buf == nil {
			return "", eris.New("malloc failed")
		}

		var grp C.struct_group
		var result *C.struct_group
		rc := C.getgrgid_r(
			C.gid_t(gid),
			&grp,
			(*C.char)(buf),
			C.size_t(bufSize),
			&result,
		)

		if rc == C.ERANGE {
			C.free(buf)
			bufSize *= 2
			if bufSize > maxGroupEntrySize {
				return "", eris.Errorf("group entry %q is too large", FormatID(gid))
			}
			continue
		}

		if rc != 0 {
			C.free(buf)
			return "", eris.Errorf("getgrgid_r(%q): %s", FormatID(gid), C.GoString(C.strerror(rc)))
		}
		if result == nil {
			C.free(buf)
			return "", eris.Errorf("group %q not found", FormatID(gid))
		}

		name := C.GoString(result.gr_name)
		C.free(buf)
		return name, nil
	}
}

func getgrouplist(username string, primaryGroupID GUID) ([]GUID, error) {
	cusername := C.CString(username)
	defer C.free(unsafe.Pointer(cusername))

	groupCount := C.int(initialGroupCount)
	for {
		if groupCount <= 0 || groupCount > maxGroupCount {
			return nil, eris.Errorf("group count for user %q exceeds limit %d", username, maxGroupCount)
		}

		buf := C.malloc(C.size_t(groupCount) * C.size_t(C.sizeof_gid_t))
		if buf == nil {
			return nil, eris.New("malloc failed")
		}

		allocatedCount := groupCount
		rc := C.getgrouplist(
			cusername,
			C.gid_t(primaryGroupID),
			(*C.gid_t)(buf),
			&groupCount,
		)
		if rc == -1 {
			C.free(buf)
			if groupCount <= allocatedCount {
				groupCount = allocatedCount * 2
			}
			continue
		}

		if groupCount < 0 || groupCount > allocatedCount {
			C.free(buf)
			return nil, eris.Errorf("getgrouplist(%q) returned invalid group count %d", username, int(groupCount))
		}

		cgroups := unsafe.Slice((*C.gid_t)(buf), int(groupCount))
		groups := make([]GUID, len(cgroups))
		for i, gid := range cgroups {
			groups[i] = GUID(gid)
		}
		C.free(buf)
		return groups, nil
	}
}
