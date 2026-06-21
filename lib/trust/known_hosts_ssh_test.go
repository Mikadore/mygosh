package trust

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestParseKnownHostsRetainsEntriesAndMatchSkipsRevoked(t *testing.T) {
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

	firstExpected := serverOne.PublicKey()
	firstExpected.Comment = "ignored-one"
	secondExpected := serverTwo.PublicKey()
	secondExpected.Comment = "ignored-two"

	require.Equal(t, &KnownHosts{
		entries: []KnownHostEntry{
			{
				Marker:  KnownHostEmptyMarker,
				Hosts:   []string{"server.example.test", "127.0.0.1"},
				HostKey: firstExpected,
			},
			{
				Marker:  KnownHostRevoked,
				Hosts:   []string{"revoked.example.test"},
				HostKey: secondExpected,
			},
		},
	}, got)

	matched, ok := got.Match(func(entry *KnownHostEntry) bool {
		return entry.MatchesValid("server.example.test")
	})
	require.True(t, ok)
	require.True(t, matched.HostKey.Equal(serverOne.PublicKey()))

	_, ok = got.Match(func(entry *KnownHostEntry) bool {
		return entry.MatchesValid("revoked.example.test")
	})
	require.False(t, ok)
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

	left["left.example.test"][0] = rightKey.PublicKey()
	right["shared.example.test"][0] = leftKey.PublicKey()

	require.Equal(t, leftKey.PublicKey(), joined["left.example.test"][0])
	require.Equal(t, sharedKey.PublicKey(), joined["shared.example.test"][0])
	require.Equal(t, rightKey.PublicKey(), joined["shared.example.test"][1])
}

func knownHostsLine(t *testing.T, hosts []string, publicKey keys.PublicKey, comment string) string {
	t.Helper()

	encoded, err := publicKey.MarshalBinary()
	require.NoError(t, err)

	line := strings.Join(hosts, ",") + " " + ssh.KeyAlgoED25519 + " " + base64.StdEncoding.EncodeToString(encoded)
	if comment != "" {
		line += " " + comment
	}
	return line
}
