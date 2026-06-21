package trust

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestParseAuthorizedKeysRetainsOptions(t *testing.T) {
	firstKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	secondKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	contents := strings.Join([]string{
		"# leading comment",
		`command="echo hi",no-pty ` + authorizedKeysLine(t, firstKey.PublicKey(), "user-one"),
		`environment="LANG=C.UTF-8",environment="LC_ALL=C",restrict ` + authorizedKeysLine(t, secondKey.PublicKey(), "user-two"),
		"",
	}, "\n")

	got, err := ParseAuthorizedKeys([]byte(contents))
	require.NoError(t, err)

	firstExpected := firstKey.PublicKey()
	firstExpected.Comment = "user-one"
	secondExpected := secondKey.PublicKey()
	secondExpected.Comment = "user-two"

	require.Equal(t, &AuthorizedKeys{
		entries: []AuthorizedKeyEntry{
			{
				Options: []AuthorizedKeyOption{
					{Name: "command", Value: `"echo hi"`, HasValue: true},
					{Name: "no-pty"},
				},
				Key: firstExpected,
			},
			{
				Options: []AuthorizedKeyOption{
					{Name: "environment", Value: `"LANG=C.UTF-8"`, HasValue: true},
					{Name: "environment", Value: `"LC_ALL=C"`, HasValue: true},
					{Name: "restrict"},
				},
				Key: secondExpected,
			},
		},
	}, got)
}

func TestAuthorizedKeysMatchAcceptsOptionBearingEntries(t *testing.T) {
	allowedKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	rejectedKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	authorized, err := ParseAuthorizedKeys([]byte(`restrict ` + authorizedKeysLine(t, allowedKey.PublicKey(), "allowed")))
	require.NoError(t, err)

	_, ok := authorized.Match(func(entry *AuthorizedKeyEntry) bool {
		return entry.Key.Equal(allowedKey.PublicKey())
	})
	require.True(t, ok)

	_, ok = authorized.Match(func(entry *AuthorizedKeyEntry) bool {
		return entry.Key.Equal(rejectedKey.PublicKey())
	})
	require.False(t, ok)
}

func authorizedKeysLine(t *testing.T, publicKey keys.PublicKey, comment string) string {
	t.Helper()

	encoded, err := publicKey.MarshalBinary()
	require.NoError(t, err)

	line := ssh.KeyAlgoED25519 + " " + base64.StdEncoding.EncodeToString(encoded)
	if comment != "" {
		line += " " + comment
	}
	return line
}
