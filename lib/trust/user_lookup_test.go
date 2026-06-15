package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestResolveAuthorizedKeysPathsExpandsHomeDir(t *testing.T) {
	got := resolveAuthorizedKeysPaths("/home/alice", []string{
		"~/.mygosh/authorized_keys",
		"/etc/mygosh/authorized_keys",
	})

	require.Equal(t, []string{
		"/home/alice/.mygosh/authorized_keys",
		"/etc/mygosh/authorized_keys",
	}, got)
}

func TestGatherAuthorizedKeysSkipsMissingFiles(t *testing.T) {
	keypair, err := keys.GenerateEd25519()
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "authorized_keys")
	line := authorizedKeysLine(t, keypair.PublicKey(), "alice@test")
	require.NoError(t, os.WriteFile(path, []byte(line+"\n"), 0o600))

	got, err := GatherAuthorizedKeys([]string{
		filepath.Join(t.TempDir(), "missing"),
		path,
	})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, 0, got[0].Compare(keypair.PublicKey()))
}

func TestAuthorizedKeysClientAuthorizerMatchesKeyForUser(t *testing.T) {
	currentUser, err := user.Current()
	require.NoError(t, err)

	keypair, err := keys.GenerateEd25519()
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "authorized_keys")
	line := authorizedKeysLine(t, keypair.PublicKey(), "alice@test")
	require.NoError(t, os.WriteFile(path, []byte(line+"\n"), 0o600))

	authorizer := AuthorizedKeysClientAuthorizer([]string{path})
	err = authorizer(auth.ClientIdentity{
		Username:  currentUser.Username,
		PublicKey: keypair.PublicKey(),
	})
	require.NoError(t, err)
}

func TestAuthorizedKeysClientAuthorizerRejectsUnexpectedKey(t *testing.T) {
	currentUser, err := user.Current()
	require.NoError(t, err)

	authorizedKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	presentedKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "authorized_keys")
	line := authorizedKeysLine(t, authorizedKey.PublicKey(), "alice@test")
	require.NoError(t, os.WriteFile(path, []byte(line+"\n"), 0o600))

	authorizer := AuthorizedKeysClientAuthorizer([]string{path})
	err = authorizer(auth.ClientIdentity{
		Username:  currentUser.Username,
		PublicKey: presentedKey.PublicKey(),
	})
	require.ErrorContains(t, err, "client public key is not authorized")
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
