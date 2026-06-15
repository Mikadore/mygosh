package trust

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const testOpenSSHPrivateKeyPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDoug3CDZVZjUK8S1oJpkCz2PvHUJLpWQpsi8cCjCxk4gAAAJheWNBdXljQ
XQAAAAtzc2gtZWQyNTUxOQAAACDoug3CDZVZjUK8S1oJpkCz2PvHUJLpWQpsi8cCjCxk4g
AAAEC7yFFm0wPZscFzqoNwYSWhatJoKiKK0ytbrvzru/hHn+i6DcINlVmNQrxLWgmmQLPY
+8dQkulZCmyLxwKMLGTiAAAAEm1pa2Fkb3JlQGFyY2hsaW51eAECAw==
-----END OPENSSH PRIVATE KEY-----
`

func TestResolveCurrentUserPathExpandsHomeDir(t *testing.T) {
	homeDir := t.TempDir()

	got, err := resolveCurrentUserPathWithHomeDir(homeDir, "~/.mygosh/id_ed25519")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(homeDir, ".mygosh", "id_ed25519"), got)
}

func TestLookupHostKeyReadsOpenSSHPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_ed25519")
	require.NoError(t, os.WriteFile(path, []byte(testOpenSSHPrivateKeyPEM), 0o600))

	keypair, err := LookupHostKey(path)
	require.NoError(t, err)
	require.Equal(t, "mikadore@archlinux", keypair.Comment)
	require.Equal(t, "e8ba0dc20d95598d42bc4b5a09a640b3d8fbc75092e9590a6c8bc7028c2c64e2", hex.EncodeToString(keypair.Public))
}

func TestLookupClientIdentityReadsOpenSSHPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(path, []byte(testOpenSSHPrivateKeyPEM), 0o600))

	keypair, err := LookupClientIdentity(path)
	require.NoError(t, err)
	require.Equal(t, "mikadore@archlinux", keypair.Comment)
	require.Equal(t, "bbc85166d303d9b1c173aa83706125a16ad2682a228ad32b5baefcebbbf8479f", hex.EncodeToString(keypair.Private))
}
