package trust

import (
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	charmlog "github.com/charmbracelet/log"
	"github.com/rotisserie/eris"
)

const DefaultKnownHostsPath = "~/.mygosh/known_hosts"

func KnownHostsHostKeyVerifier(path string) auth.HostKeyVerifier {
	return KnownHostsHostKeyVerifierWithLogger(path, nil)
}

func KnownHostsHostKeyVerifierWithLogger(path string, logger *charmlog.Logger) auth.HostKeyVerifier {
	logger = logging.Resolve(logger)
	return func(referenceIdentity string, hostKey keys.PublicKey) error {
		resolvedPath, err := resolveCurrentUserPath(path)
		if err != nil {
			return eris.Wrap(err, "resolve known_hosts path")
		}

		logger.Debug("loading known_hosts", "path", resolvedPath, "reference_identity", referenceIdentity)

		knownHosts, err := ReadKnownHosts(resolvedPath)
		if err != nil {
			return eris.Wrap(err, "load known_hosts")
		}

		hostKeys, ok := knownHosts[referenceIdentity]
		if !ok || len(hostKeys) == 0 {
			return eris.Errorf("no known host keys for reference identity %q", referenceIdentity)
		}

		for _, knownHostKey := range hostKeys {
			if knownHostKey.Compare(hostKey) != 0 {
				continue
			}

			logger.Info("known_hosts matched server identity", "reference_identity", referenceIdentity, "fingerprint", hostKey.FingerprintSHA256())
			return nil
		}

		return eris.Errorf("unexpected host key fingerprint %s for reference identity %q", hostKey.FingerprintSHA256(), referenceIdentity)
	}
}
