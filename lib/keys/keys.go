package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/rotisserie/eris"
	"golang.org/x/crypto/curve25519"
)

type Algorithm string

const (
	AlgorithmX25519  Algorithm = "x25519"
	AlgorithmEd25519 Algorithm = "ed25519"
)

const (
	x25519KeyMaterialSize = 32
	ed25519PublicKeySize  = ed25519.PublicKeySize
	ed25519SeedSize       = ed25519.SeedSize
	privateKeyMagic       = "mygosh-private-key-v1"
	publicKeyMagic        = "mygosh-public-key-v1"
)

type PublicKey struct {
	Algorithm Algorithm
	Bytes     []byte
}

type Keypair struct {
	Algorithm Algorithm
	Public    []byte
	Private   []byte
	Comment   string
}

func Generate(alg Algorithm) (Keypair, error) {
	switch alg {
	case AlgorithmX25519:
		return GenerateX25519()
	case AlgorithmEd25519:
		return GenerateEd25519()
	default:
		return Keypair{}, eris.Errorf("generate keypair: unsupported algorithm %q", alg)
	}
}

func GenerateX25519() (Keypair, error) {
	private := make([]byte, x25519KeyMaterialSize)
	if _, err := rand.Read(private); err != nil {
		return Keypair{}, eris.Wrap(err, "generate x25519 private key")
	}

	public, err := deriveX25519Public(private)
	if err != nil {
		return Keypair{}, err
	}

	return Keypair{
		Algorithm: AlgorithmX25519,
		Public:    public,
		Private:   private,
	}, nil
}

func GenerateEd25519() (Keypair, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, eris.Wrap(err, "generate ed25519 key")
	}

	return Keypair{
		Algorithm: AlgorithmEd25519,
		Public:    cloneBytes(public),
		Private:   cloneBytes(private.Seed()),
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
		Algorithm: AlgorithmEd25519,
		Public:    public,
		Private:   cloneBytes(seed),
	}, nil
}

func (k Keypair) PublicKey() PublicKey {
	return PublicKey{
		Algorithm: k.Algorithm,
		Bytes:     cloneBytes(k.Public),
	}
}

func (k PublicKey) Validate() error {
	if err := validateAlgorithm(k.Algorithm); err != nil {
		return err
	}

	switch k.Algorithm {
	case AlgorithmX25519:
		return validateKeyLength(k.Bytes, x25519KeyMaterialSize, "public")
	case AlgorithmEd25519:
		return validateKeyLength(k.Bytes, ed25519PublicKeySize, "public")
	default:
		return eris.Errorf("validate public key: unsupported algorithm %q", k.Algorithm)
	}
}

func (k Keypair) Validate() error {
	if err := validateAlgorithm(k.Algorithm); err != nil {
		return err
	}

	switch k.Algorithm {
	case AlgorithmX25519:
		if err := validateKeyLength(k.Public, x25519KeyMaterialSize, "public"); err != nil {
			return err
		}
		if err := validateKeyLength(k.Private, x25519KeyMaterialSize, "private"); err != nil {
			return err
		}

		derived, err := deriveX25519Public(k.Private)
		if err != nil {
			return err
		}
		if !bytes.Equal(derived, k.Public) {
			return eris.New("x25519 keypair public key does not match private key")
		}
		return nil
	case AlgorithmEd25519:
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
	default:
		return eris.Errorf("validate keypair: unsupported algorithm %q", k.Algorithm)
	}
}

func (k Keypair) MarshalBinary() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}

	enc := bincoder.NewEncoder()
	enc.Write([]byte(privateKeyMagic))
	enc.UTF8String(string(k.Algorithm))
	enc.Bytes(k.Public)
	enc.Bytes(k.Private)
	enc.UTF8String(k.Comment)
	if err := enc.Err(); err != nil {
		return nil, eris.Wrap(err, "encode private key")
	}
	return append([]byte(nil), enc.Result()...), nil
}

func ParseKeypair(b []byte) (Keypair, error) {
	dec := bincoder.NewCursor(b).WithMaxBytes(16 * 1024)
	dec.ExpectBytes([]byte(privateKeyMagic))

	alg := Algorithm(dec.UTF8String())
	publicBytes := dec.Bytes()
	privateBytes := dec.Bytes()
	comment := dec.UTF8String()
	if err := dec.Done(); err != nil {
		return Keypair{}, eris.Wrap(err, "decode private key")
	}

	if err := validateAlgorithm(alg); err != nil {
		return Keypair{}, err
	}

	keypair := Keypair{
		Algorithm: alg,
		Public:    cloneBytes(publicBytes),
		Private:   cloneBytes(privateBytes),
		Comment:   comment,
	}
	if err := keypair.Validate(); err != nil {
		return Keypair{}, eris.Wrap(err, "decode private key")
	}
	return keypair, nil
}

func (k PublicKey) MarshalBinary() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}

	enc := bincoder.NewEncoder()
	enc.Write([]byte(publicKeyMagic))
	enc.UTF8String(string(k.Algorithm))
	enc.Bytes(k.Bytes)
	if err := enc.Err(); err != nil {
		return nil, eris.Wrap(err, "encode public key")
	}
	return append([]byte(nil), enc.Result()...), nil
}

func ParsePublicKey(b []byte) (PublicKey, error) {
	dec := bincoder.NewCursor(b).WithMaxBytes(16 * 1024)
	dec.ExpectBytes([]byte(publicKeyMagic))

	alg := Algorithm(dec.UTF8String())
	keyBytes := dec.Bytes()
	if err := dec.Done(); err != nil {
		return PublicKey{}, eris.Wrap(err, "decode public key")
	}

	if err := validateAlgorithm(alg); err != nil {
		return PublicKey{}, err
	}

	key := PublicKey{
		Algorithm: alg,
		Bytes:     cloneBytes(keyBytes),
	}
	if err := key.Validate(); err != nil {
		return PublicKey{}, eris.Wrap(err, "decode public key")
	}
	return key, nil
}

func (k Keypair) MarshalBase64() (string, error) {
	b, err := k.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func ParseKeypairBase64(s string) (Keypair, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Keypair{}, eris.Wrap(err, "decode private key base64")
	}
	return ParseKeypair(b)
}

func MustParseKeypairBase64(s string) Keypair {
	keypair, err := ParseKeypairBase64(s)
	if err != nil {
		panic(err)
	}
	return keypair
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
	case AlgorithmX25519, AlgorithmEd25519:
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

func deriveX25519Public(private []byte) ([]byte, error) {
	if err := validateKeyLength(private, x25519KeyMaterialSize, "private"); err != nil {
		return nil, eris.Wrap(err, "derive x25519 public key")
	}

	derived, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, eris.Wrap(err, "derive x25519 public key")
	}
	return cloneBytes(derived), nil
}

func deriveEd25519Public(seed []byte) ([]byte, error) {
	if err := validateKeyLength(seed, ed25519SeedSize, "private"); err != nil {
		return nil, eris.Wrap(err, "derive ed25519 public key")
	}

	private := ed25519.NewKeyFromSeed(seed)
	return cloneBytes(private.Public().(ed25519.PublicKey)), nil
}
