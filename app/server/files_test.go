package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const testOpenSSHHostKeyPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDoug3CDZVZjUK8S1oJpkCz2PvHUJLpWQpsi8cCjCxk4gAAAJheWNBdXljQ
XQAAAAtzc2gtZWQyNTUxOQAAACDoug3CDZVZjUK8S1oJpkCz2PvHUJLpWQpsi8cCjCxk4g
AAAEC7yFFm0wPZscFzqoNwYSWhatJoKiKK0ytbrvzru/hHn+i6DcINlVmNQrxLWgmmQLPY
+8dQkulZCmyLxwKMLGTiAAAAEm1pa2Fkb3JlQGFyY2hsaW51eAECAw==
-----END OPENSSH PRIVATE KEY-----
`

func TestLoadHostKeyRequiresPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_ed25519")
	require.NoError(t, os.WriteFile(path, []byte(testOpenSSHHostKeyPEM), 0o600))

	keypair, err := loadHostKey(path, nil)
	require.NoError(t, err)
	require.NoError(t, keypair.Validate())

	require.NoError(t, os.Chmod(path, 0o644))
	_, err = loadHostKey(path, nil)
	require.ErrorContains(t, err, "read permission")
}

func TestLoadHostKeyRejectsMalformedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_ed25519")
	require.NoError(t, os.WriteFile(path, []byte("not a private key"), 0o600))
	_, err := loadHostKey(path, nil)
	require.ErrorContains(t, err, "parse host key")
}
