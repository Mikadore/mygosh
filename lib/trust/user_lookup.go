package trust

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	charmlog "github.com/charmbracelet/log"
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

func AuthorizedKeysClientKeyAuthorizer(paths []string) auth.ClientKeyAuthorizer {
	return AuthorizedKeysClientKeyAuthorizerWithLogger(paths, nil)
}

func AuthorizedKeysClientKeyAuthorizerWithLogger(paths []string, logger *charmlog.Logger) auth.ClientKeyAuthorizer {
	configuredPaths := append([]string(nil), paths...)
	logger = logging.Resolve(logger)

	return auth.ClientKeyAuthorizerFunc(func(_ context.Context, req auth.ClientKeyAuthorizationRequest) (auth.ClientKeyAuthorizationResult, error) {
		identity := req.Identity

		account, err := user.Lookup(identity.Username)
		if err != nil {
			return auth.ClientKeyAuthorizationResult{}, eris.Wrapf(err, "lookup local user %q", identity.Username)
		}

		resolvedPaths := resolveAuthorizedKeysPaths(account.HomeDir, configuredPaths)
		logger.Debug("gathering authorized_keys", "username", identity.Username, "files", resolvedPaths)

		matchedPath, authorizedKeyCount, gatherErr := matchAuthorizedKey(resolvedPaths, identity.PublicKey)
		if matchedPath != "" {
			logger.Info("authorized client key matched local user", "username", identity.Username, "uid", account.Uid, "gid", account.Gid, "source", matchedPath, "fingerprint", identity.PublicKey.FingerprintSHA256())
			return auth.ClientKeyAuthorizationResult{
				Source: matchedPath,
				Account: auth.LocalAccount{
					Username: account.Username,
					UID:      account.Uid,
					GID:      account.Gid,
					Name:     account.Name,
					HomeDir:  account.HomeDir,
				},
			}, nil
		}
		if gatherErr != nil {
			return auth.ClientKeyAuthorizationResult{}, eris.Wrapf(gatherErr, "load authorized_keys for user %q", identity.Username)
		}
		if authorizedKeyCount == 0 {
			return auth.ClientKeyAuthorizationResult{}, eris.Errorf("no authorized keys found for user %q", identity.Username)
		}
		return auth.ClientKeyAuthorizationResult{}, eris.Errorf("client public key is not authorized for user %q", identity.Username)
	})
}

func matchAuthorizedKey(paths []string, presentedKey keys.PublicKey) (string, int, error) {
	var errs error
	authorizedKeyCount := 0

	for _, path := range paths {
		authorizedKeys, err := ReadAuthorizedKeys(path)
		if err != nil {
			if !eris.Is(err, os.ErrNotExist) {
				errs = errors.Join(errs, err)
			}
			continue
		}

		authorizedKeyCount += len(authorizedKeys)
		for _, authorizedKey := range authorizedKeys {
			if authorizedKey.Compare(presentedKey) == 0 {
				return path, authorizedKeyCount, nil
			}
		}
	}

	return "", authorizedKeyCount, errs
}

func resolveAuthorizedKeysPaths(homeDir string, paths []string) []string {
	return lo.Map(paths, func(path string, _ int) string {
		if !strings.HasPrefix(path, "~/") {
			return path
		}
		return filepath.Join(homeDir, strings.TrimPrefix(path, "~/"))
	})
}
