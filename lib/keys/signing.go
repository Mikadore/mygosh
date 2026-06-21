package keys

import "crypto/ed25519"

type Signature = []byte

func (k *Keypair) Sign(msg []byte) Signature {
	if k == nil || k.Validate() != nil {
		panic("keys: Sign requires a valid ed25519 keypair")
	}

	return append(Signature(nil), ed25519.Sign(ed25519.NewKeyFromSeed(k.private), msg)...)
}

func (k *Keypair) Verify(msg []byte, sig Signature) bool {
	if k == nil || k.Validate() != nil {
		panic("keys: Verify requires a valid ed25519 keypair")
	}

	public := k.PublicKey()
	return (&public).Verify(msg, sig)
}

func (k *PublicKey) Verify(msg []byte, sig Signature) bool {
	if k == nil || k.Validate() != nil {
		panic("keys: Verify requires a valid ed25519 public key")
	}

	return ed25519.Verify(ed25519.PublicKey(k.bytes), msg, sig)
}
