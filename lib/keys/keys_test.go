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
