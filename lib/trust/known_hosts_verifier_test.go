package trust

import (
	"testing"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/stretchr/testify/require"
)

func TestKnownHostsHostKeyVerifierMatchesKnownHost(t *testing.T) {
	serverKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	path := writeKnownHostsFile(t, []string{"server.example.test"}, serverKey.PublicKey(), "ignored")

	verify := KnownHostsHostKeyVerifier(path)
	err = verify("server.example.test", serverKey.PublicKey())
	require.NoError(t, err)
}

func TestKnownHostsHostKeyVerifierRejectsUnknownReferenceIdentity(t *testing.T) {
	serverKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	path := writeKnownHostsFile(t, []string{"server.example.test"}, serverKey.PublicKey(), "ignored")

	verify := KnownHostsHostKeyVerifier(path)
	err = verify("other.example.test", serverKey.PublicKey())
	require.ErrorContains(t, err, "no known host keys for reference identity")
}

func TestKnownHostsHostKeyVerifierRejectsUnexpectedHostKey(t *testing.T) {
	serverKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	otherKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	path := writeKnownHostsFile(t, []string{"server.example.test"}, serverKey.PublicKey(), "ignored")

	verify := KnownHostsHostKeyVerifier(path)
	err = verify("server.example.test", otherKey.PublicKey())
	require.ErrorContains(t, err, "unexpected host key fingerprint")
}
