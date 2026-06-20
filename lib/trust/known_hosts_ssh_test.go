package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestParseKnownHostsIgnoresCommentsAndRevokedEntries(t *testing.T) {
	serverOne, err := keys.GenerateEd25519()
	require.NoError(t, err)
	serverTwo, err := keys.GenerateEd25519()
	require.NoError(t, err)

	contents := strings.Join([]string{
		"# leading comment",
		knownHostsLine(t, []string{"server.example.test", "127.0.0.1"}, serverOne.PublicKey(), "ignored-one"),
		"@revoked " + knownHostsLine(t, []string{"revoked.example.test"}, serverTwo.PublicKey(), "ignored-two"),
		"",
	}, "\n")

	got, err := ParseKnownHosts([]byte(contents))
	require.NoError(t, err)

	expectedKey := serverOne.PublicKey()
	expectedKey.Comment = ""

	require.Equal(t, map[string][]keys.PublicKey{
		"server.example.test": {expectedKey},
		"127.0.0.1":           {expectedKey},
	}, got)
	require.NotContains(t, got, "revoked.example.test")
}

func TestJoinHostPublicKeys(t *testing.T) {
	leftKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	rightKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	sharedKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	left := map[string][]keys.PublicKey{
		"left.example.test":   {leftKey.PublicKey()},
		"shared.example.test": {sharedKey.PublicKey()},
	}
	right := map[string][]keys.PublicKey{
		"shared.example.test": {rightKey.PublicKey()},
		"right.example.test":  {rightKey.PublicKey()},
	}

	joined := JoinHostPublicKeys(left, right)

	require.Equal(t, map[string][]keys.PublicKey{
		"left.example.test":   {leftKey.PublicKey()},
		"shared.example.test": {sharedKey.PublicKey(), rightKey.PublicKey()},
		"right.example.test":  {rightKey.PublicKey()},
	}, joined)

	left["left.example.test"][0].Bytes[0] ^= 0xff
	right["shared.example.test"][0].Bytes[0] ^= 0xff

	require.Equal(t, leftKey.PublicKey(), joined["left.example.test"][0])
	require.Equal(t, sharedKey.PublicKey(), joined["shared.example.test"][0])
	require.Equal(t, rightKey.PublicKey(), joined["shared.example.test"][1])
}

func knownHostsLine(t *testing.T, hosts []string, publicKey keys.PublicKey, comment string) string {
	t.Helper()

	sshPublicKey, err := ssh.NewPublicKey(ed25519.PublicKey(publicKey.Bytes))
	require.NoError(t, err)

	line := strings.Join(hosts, ",") + " " + sshPublicKey.Type() + " " + base64.StdEncoding.EncodeToString(sshPublicKey.Marshal())
	if comment != "" {
		line += " " + comment
	}
	return line
}
