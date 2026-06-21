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
	require.Equal(t, AuthorizedKeys{
		Entries: []AuthorizedKeyEntry{
			{
				Options: []AuthorizedKeyOption{
					{Name: "command", Value: `"echo hi"`, HasValue: true},
					{Name: "no-pty"},
				},
				Key: keys.PublicKey{
					Algorithm: firstKey.PublicKey().Algorithm,
					Bytes:     append([]byte(nil), firstKey.PublicKey().Bytes...),
					Comment:   "user-one",
				},
			},
			{
				Options: []AuthorizedKeyOption{
					{Name: "environment", Value: `"LANG=C.UTF-8"`, HasValue: true},
					{Name: "environment", Value: `"LC_ALL=C"`, HasValue: true},
					{Name: "restrict"},
				},
				Key: keys.PublicKey{
					Algorithm: secondKey.PublicKey().Algorithm,
					Bytes:     append([]byte(nil), secondKey.PublicKey().Bytes...),
					Comment:   "user-two",
				},
			},
		},
	}, got)
}

func TestMatchAuthorizedKeyAcceptsOptionBearingEntries(t *testing.T) {
	allowedKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	rejectedKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	authorized, err := ParseAuthorizedKeys([]byte(`restrict ` + authorizedKeysLine(t, allowedKey.PublicKey(), "allowed")))
	require.NoError(t, err)

	require.True(t, MatchAuthorizedKey(authorized, allowedKey.PublicKey()))
	require.False(t, MatchAuthorizedKey(authorized, rejectedKey.PublicKey()))
}

func authorizedKeysLine(t *testing.T, publicKey keys.PublicKey, comment string) string {
	t.Helper()

	sshPublicKey, err := ssh.NewPublicKey(ed25519.PublicKey(publicKey.Bytes))
	require.NoError(t, err)

	line := sshPublicKey.Type() + " " + base64.StdEncoding.EncodeToString(sshPublicKey.Marshal())
	if comment != "" {
		line += " " + comment
	}
	return line
}
