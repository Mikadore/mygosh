package trust

import (
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/rotisserie/eris"
	"github.com/samber/lo"
	"golang.org/x/crypto/ssh"
)

func JoinHostPublicKeys(left map[string][]keys.PublicKey, right map[string][]keys.PublicKey) map[string][]keys.PublicKey {
	merged := lo.MapEntries(left, func(host string, publicKeys []keys.PublicKey) (string, []keys.PublicKey) {
		return host, clonePublicKeys(publicKeys)
	})

	for host, publicKeys := range right {
		merged[host] = append(merged[host], clonePublicKeys(publicKeys)...)
	}

	return merged
}

func clonePublicKeys(publicKeys []keys.PublicKey) []keys.PublicKey {
	return lo.Map(publicKeys, func(publicKey keys.PublicKey, _ int) keys.PublicKey {
		return publicKey.Clone()
	})
}

func sshEd25519PublicKey(publicKey ssh.PublicKey, comment string) (keys.PublicKey, bool, error) {
	parsed, ok, err := keys.ParseSSHPublicKey(publicKey, comment)
	if err != nil {
		return keys.PublicKey{}, false, eris.Wrap(err, "parse ssh public key")
	}
	return parsed, ok, nil
}
