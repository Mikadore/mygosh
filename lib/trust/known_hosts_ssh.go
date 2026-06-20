package trust

import (
	"errors"
	"io"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/rotisserie/eris"
	"github.com/samber/lo"
	"golang.org/x/crypto/ssh"
)

func ParseKnownHosts(contents []byte) (map[string][]keys.PublicKey, error) {
	out := make(map[string][]keys.PublicKey)

	for len(contents) != 0 {
		marker, hosts, publicKey, _, rest, err := ssh.ParseKnownHosts(contents)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, eris.Wrap(err, "parse known_hosts entry")
		}
		contents = rest

		if marker == "revoked" {
			continue
		}

		parsedPublicKey, ok, err := sshEd25519PublicKey(publicKey, "")
		if err != nil {
			return nil, eris.Wrap(err, "parse known_hosts entry")
		}
		if !ok {
			continue
		}

		entry := lo.Reduce(hosts, func(acc map[string][]keys.PublicKey, host string, _ int) map[string][]keys.PublicKey {
			acc[host] = append(acc[host], clonePublicKey(parsedPublicKey))
			return acc
		}, make(map[string][]keys.PublicKey, len(hosts)))

		out = JoinHostPublicKeys(out, entry)
	}

	return out, nil
}

func MatchHostKey(knownHosts map[string][]keys.PublicKey, identity string, presented keys.PublicKey) bool {
	for _, candidate := range knownHosts[identity] {
		if candidate.Compare(presented) == 0 {
			return true
		}
	}
	return false
}
