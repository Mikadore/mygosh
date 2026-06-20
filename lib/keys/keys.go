package keys

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/rotisserie/eris"
)

type Algorithm string

const (
	AlgorithmEd25519 Algorithm = "ed25519"
)

const (
	ed25519PublicKeySize = ed25519.PublicKeySize
	ed25519SeedSize      = ed25519.SeedSize
)

type PublicKey struct {
	Algorithm Algorithm
	Bytes     []byte
	Comment   string
}

type Keypair struct {
	Public  []byte
	Private []byte
	Comment string
}

func Generate(alg Algorithm) (Keypair, error) {
	if alg == AlgorithmEd25519 {
		return GenerateEd25519()
	}
	return Keypair{}, eris.Errorf("generate keypair: unsupported algorithm %q", alg)
}

func GenerateEd25519() (Keypair, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, eris.Wrap(err, "generate ed25519 key")
	}

	return Keypair{
		Public:  cloneBytes(public),
		Private: cloneBytes(private.Seed()),
	}, nil
}

func GenerateEd25519FromSeed(seed []byte) (Keypair, error) {
	if err := validateKeyLength(seed, ed25519SeedSize, "private"); err != nil {
		return Keypair{}, eris.Wrap(err, "generate ed25519 key from seed")
	}

	public, err := deriveEd25519Public(seed)
	if err != nil {
		return Keypair{}, eris.Wrap(err, "generate ed25519 key from seed")
	}

	return Keypair{
		Public:  public,
		Private: cloneBytes(seed),
	}, nil
}

func (k Keypair) PublicKey() PublicKey {
	return PublicKey{
		Algorithm: AlgorithmEd25519,
		Bytes:     cloneBytes(k.Public),
		Comment:   k.Comment,
	}
}

func (k PublicKey) Validate() error {
	if err := validateAlgorithm(k.Algorithm); err != nil {
		return err
	}

	if k.Algorithm == AlgorithmEd25519 {
		return validateKeyLength(k.Bytes, ed25519PublicKeySize, "public")
	}
	return eris.Errorf("validate public key: unsupported algorithm %q", k.Algorithm)
}

// Compare returns a stable total ordering for public keys.
func (k PublicKey) Compare(other PublicKey) int {
	return cmp.Or(
		cmp.Compare(string(k.Algorithm), string(other.Algorithm)),
		bytes.Compare(k.Bytes, other.Bytes),
	)
}

func (k Keypair) Validate() error {
	if err := validateKeyLength(k.Public, ed25519PublicKeySize, "public"); err != nil {
		return err
	}
	if err := validateKeyLength(k.Private, ed25519SeedSize, "private"); err != nil {
		return err
	}

	derived, err := deriveEd25519Public(k.Private)
	if err != nil {
		return err
	}
	if !bytes.Equal(derived, k.Public) {
		return eris.New("ed25519 keypair public key does not match private key")
	}
	return nil
}

func ParseKeypair(b []byte) (Keypair, error) {
	return ParseOpensshPrivateKeyRaw(b)
}

func (k PublicKey) FingerprintSHA256() string {
	sum := sha256.Sum256(k.Bytes)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func (k PublicKey) IsZero() bool {
	if len(k.Bytes) == 0 {
		return true
	}
	for _, b := range k.Bytes {
		if b != 0 {
			return false
		}
	}
	return true
}

func validateAlgorithm(alg Algorithm) error {
	switch alg {
	case AlgorithmEd25519:
		return nil
	default:
		return eris.Errorf("unsupported key algorithm %q", alg)
	}
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

func validateKeyLength(b []byte, want int, label string) error {
	if len(b) != want {
		return eris.Errorf("%s key length %d does not match expected length %d", label, len(b), want)
	}
	return nil
}

func deriveEd25519Public(seed []byte) ([]byte, error) {
	if err := validateKeyLength(seed, ed25519SeedSize, "private"); err != nil {
		return nil, eris.Wrap(err, "derive ed25519 public key")
	}

	private := ed25519.NewKeyFromSeed(seed)
	return cloneBytes(private.Public().(ed25519.PublicKey)), nil
}
