package securefiles

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/Mikadore/mygosh/lib/strictfiles"
	"github.com/rotisserie/eris"
)

type Policy struct {
	OwnerID         uint32
	MaxSize         uint64
	AllowGlobalRead bool
}

// Read opens relativePath beneath anchorPath without following symlinks in any
// component below the selected anchor. Every traversed directory and the final
// file must be owned by OwnerID or root and must not be group/other writable.
func Read(anchorPath string, relativePath string, policy Policy) ([]byte, error) {
	if anchorPath == "" {
		return nil, eris.New("secure file anchor is required")
	}
	if relativePath == "" || filepath.IsAbs(relativePath) {
		return nil, eris.New("secure file path must be relative to its anchor")
	}
	if policy.MaxSize == 0 {
		return nil, eris.New("secure file maximum size is required")
	}

	components := cleanComponents(relativePath)
	if len(components) == 0 {
		return nil, eris.New("secure file path is empty")
	}

	anchor, err := strictfiles.OpenDirWithOptions(anchorPath, strictfiles.CheckOptions{
		OwnerID:         policy.OwnerID,
		AllowSymlinks:   true,
		AllowGlobalRead: true,
	})
	if err != nil {
		return nil, eris.Wrap(err, "open secure file anchor")
	}
	current := &anchor
	defer func() {
		_ = current.Close()
	}()

	for _, component := range components[:len(components)-1] {
		next, err := current.OpenAt(component, strictfiles.CheckOptions{
			WantDir:         true,
			OwnerID:         policy.OwnerID,
			AllowGlobalRead: true,
		})
		if err != nil {
			return nil, eris.Wrap(err, "open secure file directory")
		}
		if err := current.Close(); err != nil {
			_ = next.Close()
			return nil, err
		}
		current = &next
	}

	checked, err := current.OpenAt(components[len(components)-1], strictfiles.CheckOptions{
		OwnerID:         policy.OwnerID,
		AllowGlobalRead: policy.AllowGlobalRead,
		MaxSize:         policy.MaxSize,
	})
	if err != nil {
		return nil, eris.Wrap(err, "open secure file")
	}

	file := checked.ToFile()
	if file == nil {
		return nil, eris.New("secure file descriptor is unavailable")
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, int64(policy.MaxSize)+1))
	if err != nil {
		return nil, eris.Wrap(err, "read secure file")
	}
	if uint64(len(contents)) > policy.MaxSize {
		return nil, eris.Errorf("secure file exceeds maximum size %d", policy.MaxSize)
	}
	return contents, nil
}

func cleanComponents(path string) []string {
	raw := strings.Split(filepath.Clean(path), string(filepath.Separator))
	out := make([]string, 0, len(raw))
	for _, component := range raw {
		switch component {
		case "", ".":
			continue
		case "..":
			return nil
		default:
			out = append(out, component)
		}
	}
	return out
}
