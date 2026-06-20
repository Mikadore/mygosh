package server

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mikadore/mygosh/app/securefiles"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/rotisserie/eris"
)

const (
	defaultHostKeyPath = "~/.mygosh/host_ed25519"
	privateKeyMaxSize  = 16 << 10
)

func loadHostKey(path string, logger *slog.Logger) (keys.Keypair, error) {
	logger = logging.Resolve(logger)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return keys.Keypair{}, eris.Wrap(err, "resolve current user home")
	}

	var resolved, anchor, relative string
	switch {
	case strings.HasPrefix(path, "~/"):
		relative = strings.TrimPrefix(path, "~/")
		resolved = filepath.Join(homeDir, relative)
		anchor = homeDir
	case filepath.IsAbs(path):
		resolved = path
		anchor = filepath.Dir(path)
		relative = filepath.Base(path)
	default:
		anchor, err = os.Getwd()
		if err != nil {
			return keys.Keypair{}, eris.Wrap(err, "resolve current working directory")
		}
		relative = path
		resolved = filepath.Join(anchor, relative)
	}

	contents, err := securefiles.Read(anchor, relative, securefiles.Policy{
		OwnerID: uint32(os.Geteuid()),
		MaxSize: privateKeyMaxSize,
	})
	if err != nil {
		return keys.Keypair{}, eris.Wrapf(err, "load host key %q", resolved)
	}
	logger.Debug("loaded host key", "path", resolved)

	keypair, err := keys.ParseOpensshPrivateKeyRaw(contents)
	if err != nil {
		return keys.Keypair{}, eris.Wrapf(err, "parse host key %q", resolved)
	}
	return keypair, nil
}
