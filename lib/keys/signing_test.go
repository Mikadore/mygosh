package keys

import "testing"

import "github.com/stretchr/testify/require"

func TestEd25519SignAndVerify(t *testing.T) {
	keypair, err := GenerateEd25519()
	require.NoError(t, err)
	require.True(t, (&keypair).IsSigning())

	msg := []byte("sign me")
	sig := (&keypair).Sign(msg)
	require.NotEmpty(t, sig)
	require.True(t, (&keypair).Verify(msg, sig))

	public := keypair.PublicKey()
	require.True(t, (&public).Verify(msg, sig))
	require.False(t, (&public).Verify([]byte("tampered"), sig))

	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0xff
	require.False(t, (&public).Verify(msg, badSig))
}

func TestNonSigningKeysPanicOnSignAndVerify(t *testing.T) {
	keypair, err := GenerateX25519()
	require.NoError(t, err)
	require.False(t, (&keypair).IsSigning())

	require.Panics(t, func() {
		_ = (&keypair).Sign([]byte("sign me"))
	})
	require.Panics(t, func() {
		_ = (&keypair).Verify([]byte("sign me"), Signature([]byte("sig")))
	})

	public := keypair.PublicKey()
	require.Panics(t, func() {
		_ = (&public).Verify([]byte("sign me"), Signature([]byte("sig")))
	})
}
