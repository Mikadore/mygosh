package client

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mikadore/mygosh/app/securefiles"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/trust"
	"github.com/rotisserie/eris"
)

const (
	privateKeyMaxSize = 16 << 10
	knownHostsMaxSize = 1 << 20
)

func loadClientIdentity(path string) (keys.Keypair, error) {
	logger := slog.Default().With("component", "client-files")
	contents, resolved, err := readCurrentUserFile(path, privateKeyMaxSize, false)
	if err != nil {
		return keys.Keypair{}, eris.Wrap(err, "load client identity")
	}
	logger.Debug("loaded client identity", "path", resolved)
	keypair, err := keys.ParseOpensshPrivateKeyRaw(contents)
	if err != nil {
		return keys.Keypair{}, eris.Wrapf(err, "parse client identity %q", resolved)
	}
	return keypair, nil
}

func loadKnownHosts(path string) (*trust.KnownHosts, string, error) {
	logger := slog.Default().With("component", "client-files")
	contents, resolved, err := readCurrentUserFile(path, knownHostsMaxSize, true)
	if err != nil {
		return nil, "", eris.Wrap(err, "load known_hosts")
	}
	logger.Debug("loaded known_hosts", "path", resolved)
	knownHosts, err := trust.ParseKnownHosts(contents)
	if err != nil {
		return nil, "", eris.Wrapf(err, "parse known_hosts %q", resolved)
	}
	return knownHosts, resolved, nil
}

func knownHostsVerifier(knownHosts *trust.KnownHosts, source string, logger *slog.Logger) auth.HostKeyVerifier {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return auth.HostKeyVerifierFunc(func(_ context.Context, req auth.HostKeyVerificationRequest) error {
		entry, ok := knownHosts.Match(func(entry *trust.KnownHostEntry) bool {
			return entry.MatchesValid(req.ReferenceIdentity)
		})
		if !ok {
			return eris.Errorf("no known host keys for reference identity %q", req.ReferenceIdentity)
		}
		if !entry.HostKey.Equal(req.HostKey) {
			return eris.Errorf("unexpected host key fingerprint %s for reference identity %q", req.HostKey.FingerprintSHA256(), req.ReferenceIdentity)
		}
		logger.Info(
			"known_hosts matched server identity",
			"reference_identity", req.ReferenceIdentity,
			"source", source,
			"fingerprint", req.HostKey.FingerprintSHA256(),
		)
		return nil
	})
}

func readCurrentUserFile(path string, maxSize uint64, allowGlobalRead bool) ([]byte, string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, "", eris.Wrap(err, "resolve current user home")
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
			return nil, "", eris.Wrap(err, "resolve current working directory")
		}
		relative = path
		resolved = filepath.Join(anchor, relative)
	}

	contents, err := securefiles.Read(anchor, relative, securefiles.Policy{
		OwnerID:         uint32(os.Geteuid()),
		MaxSize:         maxSize,
		AllowGlobalRead: allowGlobalRead,
	})
	return contents, resolved, err
}
