package keys

import (
	"crypto/ed25519"

	"github.com/rotisserie/eris"
	"golang.org/x/crypto/ssh"
)

func ParseSSHPublicKey(publicKey ssh.PublicKey, comment string) (PublicKey, bool, error) {
	if publicKey.Type() != ssh.KeyAlgoED25519 {
		return PublicKey{}, false, nil
	}

	cryptoKey, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return PublicKey{}, false, eris.Errorf("ssh public key %q does not expose a crypto public key", publicKey.Type())
	}

	ed25519Key, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return PublicKey{}, false, eris.Errorf("ssh public key %q is not an ed25519 public key", publicKey.Type())
	}

	return PublicKey{
		Algorithm: AlgorithmEd25519,
		Bytes:     cloneBytes(ed25519Key),
		Comment:   comment,
	}, true, nil
}

func (k PublicKey) MarshalBinary() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}

	sshPublicKey, err := ssh.NewPublicKey(ed25519.PublicKey(k.Bytes))
	if err != nil {
		return nil, eris.Wrap(err, "encode public key")
	}
	return cloneBytes(sshPublicKey.Marshal()), nil
}

func ParsePublicKey(b []byte) (PublicKey, error) {
	sshPublicKey, err := ssh.ParsePublicKey(b)
	if err != nil {
		return PublicKey{}, eris.Wrap(err, "decode public key")
	}

	publicKey, ok, err := ParseSSHPublicKey(sshPublicKey, "")
	if err != nil {
		return PublicKey{}, eris.Wrap(err, "decode public key")
	}
	if !ok {
		return PublicKey{}, eris.Errorf("decode public key: unsupported public key type %q", sshPublicKey.Type())
	}
	return publicKey, nil
}
