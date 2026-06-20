package keys

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseKeypairUsesOpenSSHFormat(t *testing.T) {
	keypair, err := ParseKeypair([]byte(testOpenSSHPrivateKeyPEM))
	require.NoError(t, err)
	require.NoError(t, keypair.Validate())
	require.Equal(t, "mikadore@archlinux", keypair.Comment)
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

func TestParsePublicKeyRejectsInvalidBlob(t *testing.T) {
	_, err := ParsePublicKey([]byte("not a public key"))
	require.ErrorContains(t, err, "decode public key")
}

func TestPublicKeyFingerprintSHA256(t *testing.T) {
	keypair, err := GenerateEd25519()
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
	require.NoError(t, keypair.Validate())
	require.Len(t, keypair.Public, ed25519PublicKeySize)
	require.Len(t, keypair.Private, ed25519SeedSize)
}

func TestGenerateRejectsUnsupportedAlgorithm(t *testing.T) {
	_, err := Generate(Algorithm("x25519"))
	require.ErrorContains(t, err, "unsupported algorithm")
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
