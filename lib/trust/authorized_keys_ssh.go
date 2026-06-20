package trust

import (
	"bytes"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/rotisserie/eris"
	"golang.org/x/crypto/ssh"
)

func ParseAuthorizedKeys(contents []byte) ([]keys.PublicKey, error) {
	contents = bytes.TrimSpace(contents)

	var out []keys.PublicKey
	for len(contents) != 0 {
		pk, comment, options, rest, err := ssh.ParseAuthorizedKey(contents)
		if err != nil {
			return nil, eris.Wrap(err, "parse authorized_keys entry")
		}
		contents = bytes.TrimSpace(rest)

		if pk.Type() != ssh.KeyAlgoED25519 || len(options) != 0 {
			continue
		}

		publicKey, ok, err := sshEd25519PublicKey(pk, comment)
		if err != nil {
			return nil, eris.Wrap(err, "parse authorized_keys entry")
		}
		if !ok {
			continue
		}

		out = append(out, publicKey)
	}

	return out, nil
}

func MatchAuthorizedKey(authorized []keys.PublicKey, presented keys.PublicKey) bool {
	for _, candidate := range authorized {
		if candidate.Compare(presented) == 0 {
			return true
		}
	}
	return false
}
