package trust

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	charmlog "github.com/charmbracelet/log"
	"github.com/rotisserie/eris"
)

const (
	DefaultHostKeyPath        = "~/.mygosh/host_ed25519"
	DefaultClientIdentityPath = "~/.mygosh/id_ed25519"
)

func LookupHostKey(path string) (keys.Keypair, error) {
	return LookupHostKeyWithLogger(path, nil)
}

func LookupClientIdentity(path string) (keys.Keypair, error) {
	return LookupClientIdentityWithLogger(path, nil)
}

func LookupHostKeyWithLogger(path string, logger *charmlog.Logger) (keys.Keypair, error) {
	return lookupPrivateKey("host key", path, logger)
}

func LookupClientIdentityWithLogger(path string, logger *charmlog.Logger) (keys.Keypair, error) {
	return lookupPrivateKey("client identity", path, logger)
}

func lookupPrivateKey(label string, path string, logger *charmlog.Logger) (keys.Keypair, error) {
	resolvedPath, err := resolveCurrentUserPath(path)
	if err != nil {
		return keys.Keypair{}, eris.Wrapf(err, "resolve %s path", label)
	}

	logging.Resolve(logger).Debug("loading private key", "label", label, "path", resolvedPath)

	keypair, err := keys.ParseOpensshPrivateKeyFile(resolvedPath)
	if err != nil {
		return keys.Keypair{}, eris.Wrapf(err, "load %s", label)
	}

	return keypair, nil
}

func resolveCurrentUserPath(path string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return resolveCurrentUserPathWithHomeDir(homeDir, path)
}

func resolveCurrentUserPathWithHomeDir(homeDir string, path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}

	return filepath.Join(homeDir, strings.TrimPrefix(path, "~/")), nil
}
