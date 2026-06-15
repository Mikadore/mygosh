package trust

import (
	"context"
	"testing"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/stretchr/testify/require"
)

func TestKnownHostsHostKeyVerifierMatchesKnownHost(t *testing.T) {
	serverKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	path := writeKnownHostsFile(t, []string{"server.example.test"}, serverKey.PublicKey(), "ignored")

	verify := KnownHostsHostKeyVerifier(path)
	err = verify.VerifyHostKey(context.Background(), auth.HostKeyVerificationRequest{
		ReferenceIdentity: "server.example.test",
		HostKey:           serverKey.PublicKey(),
	})
	require.NoError(t, err)
}

func TestKnownHostsHostKeyVerifierRejectsUnknownReferenceIdentity(t *testing.T) {
	serverKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	path := writeKnownHostsFile(t, []string{"server.example.test"}, serverKey.PublicKey(), "ignored")

	verify := KnownHostsHostKeyVerifier(path)
	err = verify.VerifyHostKey(context.Background(), auth.HostKeyVerificationRequest{
		ReferenceIdentity: "other.example.test",
		HostKey:           serverKey.PublicKey(),
	})
	require.ErrorContains(t, err, "no known host keys for reference identity")
}

func TestKnownHostsHostKeyVerifierRejectsUnexpectedHostKey(t *testing.T) {
	serverKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	otherKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	path := writeKnownHostsFile(t, []string{"server.example.test"}, serverKey.PublicKey(), "ignored")

	verify := KnownHostsHostKeyVerifier(path)
	err = verify.VerifyHostKey(context.Background(), auth.HostKeyVerificationRequest{
		ReferenceIdentity: "server.example.test",
		HostKey:           otherKey.PublicKey(),
	})
	require.ErrorContains(t, err, "unexpected host key fingerprint")
}
