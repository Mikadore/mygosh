package trust

import (
	"context"
	"log/slog"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/rotisserie/eris"
)

const DefaultKnownHostsPath = "~/.mygosh/known_hosts"

func KnownHostsHostKeyVerifier(path string) auth.HostKeyVerifier {
	return KnownHostsHostKeyVerifierWithLogger(path, nil)
}

func KnownHostsHostKeyVerifierWithLogger(path string, logger *slog.Logger) auth.HostKeyVerifier {
	logger = logging.Resolve(logger)
	return auth.HostKeyVerifierFunc(func(_ context.Context, req auth.HostKeyVerificationRequest) (auth.HostKeyVerificationResult, error) {
		resolvedPath, err := resolveCurrentUserPath(path)
		if err != nil {
			return auth.HostKeyVerificationResult{}, eris.Wrap(err, "resolve known_hosts path")
		}

		logger.Debug("loading known_hosts", "path", resolvedPath, "reference_identity", req.ReferenceIdentity)

		knownHosts, err := ReadKnownHosts(resolvedPath)
		if err != nil {
			return auth.HostKeyVerificationResult{}, eris.Wrap(err, "load known_hosts")
		}

		hostKeys, ok := knownHosts[req.ReferenceIdentity]
		if !ok || len(hostKeys) == 0 {
			return auth.HostKeyVerificationResult{}, eris.Errorf("no known host keys for reference identity %q", req.ReferenceIdentity)
		}

		for _, knownHostKey := range hostKeys {
			if knownHostKey.Compare(req.HostKey) != 0 {
				continue
			}

			logger.Info("known_hosts matched server identity", "reference_identity", req.ReferenceIdentity, "fingerprint", req.HostKey.FingerprintSHA256())
			return auth.HostKeyVerificationResult{Source: resolvedPath}, nil
		}

		return auth.HostKeyVerificationResult{}, eris.Errorf("unexpected host key fingerprint %s for reference identity %q", req.HostKey.FingerprintSHA256(), req.ReferenceIdentity)
	})
}
