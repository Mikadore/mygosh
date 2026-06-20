package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const testOpenSSHPrivateKeyPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDoug3CDZVZjUK8S1oJpkCz2PvHUJLpWQpsi8cCjCxk4gAAAJheWNBdXljQ
XQAAAAtzc2gtZWQyNTUxOQAAACDoug3CDZVZjUK8S1oJpkCz2PvHUJLpWQpsi8cCjCxk4g
AAAEC7yFFm0wPZscFzqoNwYSWhatJoKiKK0ytbrvzru/hHn+i6DcINlVmNQrxLWgmmQLPY
+8dQkulZCmyLxwKMLGTiAAAAEm1pa2Fkb3JlQGFyY2hsaW51eAECAw==
-----END OPENSSH PRIVATE KEY-----
`

func TestLoadClientIdentityRequiresPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(path, []byte(testOpenSSHPrivateKeyPEM), 0o600))

	keypair, err := loadClientIdentity(path, nil)
	require.NoError(t, err)
	require.Equal(t, keys.AlgorithmEd25519, keypair.Algorithm)

	require.NoError(t, os.Chmod(path, 0o644))
	_, err = loadClientIdentity(path, nil)
	require.ErrorContains(t, err, "read permission")
}

func TestLoadClientIdentityRejectsMalformedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(path, []byte("not a private key"), 0o600))
	_, err := loadClientIdentity(path, nil)
	require.ErrorContains(t, err, "parse client identity")
}

func TestLoadKnownHostsPermitsGlobalRead(t *testing.T) {
	serverKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	sshPublicKey, err := ssh.NewPublicKey(ed25519.PublicKey(serverKey.Public))
	require.NoError(t, err)
	line := "server.example.test " + sshPublicKey.Type() + " " + base64.StdEncoding.EncodeToString(sshPublicKey.Marshal()) + "\n"

	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte(line), 0o644))
	knownHosts, source, err := loadKnownHosts(path, nil)
	require.NoError(t, err)
	require.Equal(t, path, source)
	require.NoError(t, knownHostsVerifier(knownHosts, source, nil).VerifyHostKey(t.Context(), authHostRequest(serverKey.PublicKey())))
}

func TestLoadKnownHostsRejectsMalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte("not a known_hosts entry\n"), 0o600))
	_, _, err := loadKnownHosts(path, nil)
	require.ErrorContains(t, err, "parse known_hosts")
}

func authHostRequest(publicKey keys.PublicKey) auth.HostKeyVerificationRequest {
	return auth.HostKeyVerificationRequest{
		ReferenceIdentity: "server.example.test",
		HostKey:           publicKey,
	}
}
