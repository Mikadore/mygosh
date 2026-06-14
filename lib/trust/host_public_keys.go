package trust

import (
	"crypto/ed25519"

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
		return clonePublicKey(publicKey)
	})
}

func clonePublicKey(publicKey keys.PublicKey) keys.PublicKey {
	return keys.PublicKey{
		Algorithm: publicKey.Algorithm,
		Bytes:     append([]byte(nil), publicKey.Bytes...),
		Comment:   publicKey.Comment,
	}
}

func sshEd25519PublicKey(publicKey ssh.PublicKey, comment string) (keys.PublicKey, bool, error) {
	if publicKey.Type() != ssh.KeyAlgoED25519 {
		return keys.PublicKey{}, false, nil
	}

	cryptoKey, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return keys.PublicKey{}, false, eris.Errorf("ssh public key %q does not expose a crypto public key", publicKey.Type())
	}

	ed25519Key, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return keys.PublicKey{}, false, eris.Errorf("ssh public key %q is not an ed25519 public key", publicKey.Type())
	}

	return keys.PublicKey{
		Algorithm: keys.AlgorithmEd25519,
		Bytes:     append([]byte(nil), ed25519Key...),
		Comment:   comment,
	}, true, nil
}
