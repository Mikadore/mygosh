package keys

import (
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

const keyMaterialSize = 32
const privateKeyMagic = "mygosh-private-key-v1"

type PublicKey struct {
	Algorithm Algorithm
	Bytes     [keyMaterialSize]byte
}

type Keypair struct {
	Algorithm Algorithm
	Public    [keyMaterialSize]byte
	Private   [keyMaterialSize]byte
	Comment   string
}

func Generate(alg Algorithm) (Keypair, error) {
	switch alg {
	case AlgorithmX25519:
		return GenerateX25519()
	case AlgorithmEd25519:
		return Keypair{}, eris.Errorf("generate %s keypair: not implemented", alg)
	default:
		return Keypair{}, eris.Errorf("generate keypair: unsupported algorithm %q", alg)
	}
}

func GenerateX25519() (Keypair, error) {
	var private [keyMaterialSize]byte
	if _, err := rand.Read(private[:]); err != nil {
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

func (k Keypair) PublicKey() PublicKey {
	return PublicKey{
		Algorithm: k.Algorithm,
		Bytes:     k.Public,
	}
}

func (k Keypair) Validate() error {
	if err := validateAlgorithm(k.Algorithm); err != nil {
		return err
	}

	switch k.Algorithm {
	case AlgorithmX25519:
		derived, err := deriveX25519Public(k.Private)
		if err != nil {
			return err
		}
		if derived != k.Public {
			return eris.New("x25519 keypair public key does not match private key")
		}
		return nil
	case AlgorithmEd25519:
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
	enc.Bytes(k.Public[:])
	enc.Bytes(k.Private[:])
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

	public, err := copyKeyMaterial(publicBytes, "public")
	if err != nil {
		return Keypair{}, err
	}

	private, err := copyKeyMaterial(privateBytes, "private")
	if err != nil {
		return Keypair{}, err
	}

	keypair := Keypair{
		Algorithm: alg,
		Public:    public,
		Private:   private,
		Comment:   comment,
	}
	if err := keypair.Validate(); err != nil {
		return Keypair{}, eris.Wrap(err, "decode private key")
	}
	return keypair, nil
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
	sum := sha256.Sum256(k.Bytes[:])
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func (k PublicKey) IsZero() bool {
	return k.Bytes == [keyMaterialSize]byte{}
}

func validateAlgorithm(alg Algorithm) error {
	switch alg {
	case AlgorithmX25519, AlgorithmEd25519:
		return nil
	default:
		return eris.Errorf("unsupported key algorithm %q", alg)
	}
}

func copyKeyMaterial(b []byte, label string) ([keyMaterialSize]byte, error) {
	var out [keyMaterialSize]byte
	if len(b) != keyMaterialSize {
		return out, eris.Errorf("%s key length %d does not match expected length %d", label, len(b), keyMaterialSize)
	}
	copy(out[:], b)
	return out, nil
}

func deriveX25519Public(private [keyMaterialSize]byte) ([keyMaterialSize]byte, error) {
	var public [keyMaterialSize]byte
	derived, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return public, eris.Wrap(err, "derive x25519 public key")
	}
	copy(public[:], derived)
	return public, nil
}
