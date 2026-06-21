package keys

import "testing"

import "github.com/stretchr/testify/require"

func TestEd25519SignAndVerify(t *testing.T) {
	keypair, err := GenerateEd25519()
	require.NoError(t, err)

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

func TestInvalidKeysPanicOnSignAndVerify(t *testing.T) {
	keypair, err := GenerateEd25519()
	require.NoError(t, err)
	keypair.private = keypair.private[:len(keypair.private)-1]

	require.Panics(t, func() {
		_ = (&keypair).Sign([]byte("sign me"))
	})
	require.Panics(t, func() {
		_ = (&keypair).Verify([]byte("sign me"), Signature([]byte("sig")))
	})

	public := keypair.PublicKey()
	public.bytes = public.bytes[:len(public.bytes)-1]
	require.Panics(t, func() {
		_ = (&public).Verify([]byte("sign me"), Signature([]byte("sig")))
	})
}
