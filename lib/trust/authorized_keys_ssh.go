package trust

import (
	"bytes"
	"os"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/rotisserie/eris"
	"golang.org/x/crypto/ssh"
)

func ReadAuthorizedKeys(path string) ([]keys.PublicKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, eris.Wrapf(err, "read authorized_keys %q", path)
	}
	return ParseAuthorizedKeys(contents)
}

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
