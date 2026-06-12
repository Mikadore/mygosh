package keys

import (
	"encoding/base64"
	"testing"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/stretchr/testify/require"
)

func TestGenerateX25519EncodeDecodeRoundTrip(t *testing.T) {
	keypair, err := GenerateX25519()
	require.NoError(t, err)
	keypair.Comment = "test key"

	encoded, err := keypair.MarshalBinary()
	require.NoError(t, err)

	decoded, err := ParseKeypair(encoded)
	require.NoError(t, err)
	require.Equal(t, keypair, decoded)
}

func TestGenerateEd25519EncodeDecodeRoundTrip(t *testing.T) {
	keypair, err := GenerateEd25519()
	require.NoError(t, err)
	keypair.Comment = "test signing key"

	encoded, err := keypair.MarshalBinary()
	require.NoError(t, err)

	decoded, err := ParseKeypair(encoded)
	require.NoError(t, err)
	require.Equal(t, keypair, decoded)
}

func TestPublicKeyEncodeDecodeRoundTrip(t *testing.T) {
	keypair, err := GenerateEd25519()
	require.NoError(t, err)

	encoded, err := keypair.PublicKey().MarshalBinary()
	require.NoError(t, err)

	decoded, err := ParsePublicKey(encoded)
	require.NoError(t, err)
	require.Equal(t, keypair.PublicKey(), decoded)
}

func TestParseKeypairBase64RoundTrip(t *testing.T) {
	keypair, err := GenerateX25519()
	require.NoError(t, err)
	keypair.Comment = "base64 key"

	encoded, err := keypair.MarshalBase64()
	require.NoError(t, err)

	decoded, err := ParseKeypairBase64(encoded)
	require.NoError(t, err)
	require.Equal(t, keypair, decoded)
}

func TestParseKeypairRejectsMismatchedX25519Public(t *testing.T) {
	keypair, err := GenerateX25519()
	require.NoError(t, err)

	enc := bincoder.NewEncoder()
	enc.Write([]byte(privateKeyMagic))
	enc.UTF8String(string(AlgorithmX25519))

	badPublic := append([]byte(nil), keypair.Public...)
	badPublic[0] ^= 0xff
	enc.Bytes(badPublic)
	enc.Bytes(keypair.Private)
	enc.UTF8String("")
	require.NoError(t, enc.Err())

	_, err = ParseKeypair(enc.Result())
	require.ErrorContains(t, err, "public key does not match private key")
}

func TestParseKeypairRejectsMismatchedEd25519Public(t *testing.T) {
	keypair, err := GenerateEd25519()
	require.NoError(t, err)

	enc := bincoder.NewEncoder()
	enc.Write([]byte(privateKeyMagic))
	enc.UTF8String(string(AlgorithmEd25519))

	badPublic := append([]byte(nil), keypair.Public...)
	badPublic[0] ^= 0xff
	enc.Bytes(badPublic)
	enc.Bytes(keypair.Private)
	enc.UTF8String("")
	require.NoError(t, enc.Err())

	_, err = ParseKeypair(enc.Result())
	require.ErrorContains(t, err, "public key does not match private key")
}

func TestParseKeypairRejectsWrongX25519KeyLength(t *testing.T) {
	keypair, err := GenerateX25519()
	require.NoError(t, err)

	enc := bincoder.NewEncoder()
	enc.Write([]byte(privateKeyMagic))
	enc.UTF8String(string(AlgorithmX25519))
	enc.Bytes(keypair.Public[:31])
	enc.Bytes(keypair.Private)
	enc.UTF8String("")
	require.NoError(t, enc.Err())

	_, err = ParseKeypair(enc.Result())
	require.ErrorContains(t, err, "public key length 31 does not match expected length 32")
}

func TestPublicKeyFingerprintSHA256(t *testing.T) {
	keypair, err := GenerateX25519()
	require.NoError(t, err)

	sum := keypair.PublicKey().FingerprintSHA256()
	require.Contains(t, sum, "SHA256:")
	encoded := sum[len("SHA256:"):]

	_, err = base64.RawStdEncoding.DecodeString(encoded)
	require.NoError(t, err)
}

func TestGenerateSupportsEd25519(t *testing.T) {
	keypair, err := Generate(AlgorithmEd25519)
	require.NoError(t, err)
	require.Equal(t, AlgorithmEd25519, keypair.Algorithm)
	require.Len(t, keypair.Public, ed25519PublicKeySize)
	require.Len(t, keypair.Private, ed25519SeedSize)
}

func TestGenerateEd25519FromSeedIsDeterministic(t *testing.T) {
	seed := make([]byte, ed25519SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	first, err := GenerateEd25519FromSeed(seed)
	require.NoError(t, err)

	second, err := GenerateEd25519FromSeed(seed)
	require.NoError(t, err)

	require.Equal(t, first, second)
}
