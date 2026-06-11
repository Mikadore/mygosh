package keys

import (
	"bytes"
	"crypto/ed25519"
)

type Signature = []byte

func (k *Keypair) IsSigning() bool {
	if k == nil || k.Algorithm != AlgorithmEd25519 {
		return false
	}
	if len(k.Public) != ed25519PublicKeySize || len(k.Private) != ed25519SeedSize {
		return false
	}

	derived, err := deriveEd25519Public(k.Private)
	if err != nil {
		return false
	}
	return bytes.Equal(derived, k.Public)
}

func (k *PublicKey) IsSigning() bool {
	return isSigningPublicKey(k)
}

func (k *Keypair) Sign(msg []byte) Signature {
	if !k.IsSigning() {
		panic("keys: Sign requires an ed25519 signing keypair")
	}

	return cloneBytes(ed25519.Sign(ed25519.NewKeyFromSeed(k.Private), msg))
}

func (k *Keypair) Verify(msg []byte, sig Signature) bool {
	if !k.IsSigning() {
		panic("keys: Verify requires an ed25519 signing keypair")
	}

	public := k.PublicKey()
	return (&public).Verify(msg, sig)
}

func (k *PublicKey) Verify(msg []byte, sig Signature) bool {
	if !k.IsSigning() {
		panic("keys: Verify requires an ed25519 public key")
	}

	return ed25519.Verify(ed25519.PublicKey(k.Bytes), msg, sig)
}

func isSigningPublicKey(k *PublicKey) bool {
	return k != nil && k.Algorithm == AlgorithmEd25519 && len(k.Bytes) == ed25519PublicKeySize
}
