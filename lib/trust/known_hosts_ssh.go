package trust

import (
	"errors"
	"io"
	"os"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/rotisserie/eris"
	"github.com/samber/lo"
	"golang.org/x/crypto/ssh"
)

func ReadKnownHosts(path string) (map[string][]keys.PublicKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, eris.Wrapf(err, "read known_hosts %q", path)
	}
	return ParseKnownHosts(contents)
}

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
