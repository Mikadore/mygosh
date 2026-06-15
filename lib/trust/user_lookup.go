package trust

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/charmbracelet/log"
	"github.com/rotisserie/eris"
	"github.com/samber/lo"
)

func GatherAuthorizedKeys(files []string) ([]keys.PublicKey, error) {
	var errs error
	var out []keys.PublicKey

	for _, file := range files {
		publicKeys, err := ReadAuthorizedKeys(file)
		if err != nil {
			if !eris.Is(err, os.ErrNotExist) {
				errs = errors.Join(errs, err)
			}
			continue
		}

		out = append(out, publicKeys...)
	}

	return out, errs
}

func AuthorizedKeysClientAuthorizer(paths []string) auth.AuthorizeClientFunc {
	configuredPaths := append([]string(nil), paths...)

	return func(identity auth.ClientIdentity) error {
		account, err := user.Lookup(identity.Username)
		if err != nil {
			return eris.Wrapf(err, "lookup local user %q", identity.Username)
		}

		resolvedPaths := resolveAuthorizedKeysPaths(account.HomeDir, configuredPaths)
		log.Debug("gathering authorized_keys", "username", identity.Username, "files", resolvedPaths)

		authorizedKeys, gatherErr := GatherAuthorizedKeys(resolvedPaths)
		for _, authorizedKey := range authorizedKeys {
			if authorizedKey.Compare(identity.PublicKey) != 0 {
				continue
			}

			log.Info("authorized client key matched local user", "username", identity.Username, "fingerprint", identity.PublicKey.FingerprintSHA256())
			return nil
		}

		if gatherErr != nil {
			return eris.Wrapf(gatherErr, "load authorized_keys for user %q", identity.Username)
		}
		if len(authorizedKeys) == 0 {
			return eris.Errorf("no authorized keys found for user %q", identity.Username)
		}
		return eris.Errorf("client public key is not authorized for user %q", identity.Username)
	}
}

func resolveAuthorizedKeysPaths(homeDir string, paths []string) []string {
	return lo.Map(paths, func(path string, _ int) string {
		if !strings.HasPrefix(path, "~/") {
			return path
		}
		return filepath.Join(homeDir, strings.TrimPrefix(path, "~/"))
	})
}
