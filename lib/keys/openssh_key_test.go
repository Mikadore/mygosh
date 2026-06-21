package keys

import (
	"encoding/hex"
	"encoding/pem"
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

func TestParseOpensshPrivateKeyRawPEM(t *testing.T) {
	keypair, err := ParseOpensshPrivateKeyRaw([]byte(testOpenSSHPrivateKeyPEM))
	require.NoError(t, err)
	require.Equal(t, "mikadore@archlinux", keypair.Comment)
	require.Equal(t, "e8ba0dc20d95598d42bc4b5a09a640b3d8fbc75092e9590a6c8bc7028c2c64e2", hex.EncodeToString(keypair.public))
	require.Equal(t, "bbc85166d303d9b1c173aa83706125a16ad2682a228ad32b5baefcebbbf8479f", hex.EncodeToString(keypair.private))
	require.NoError(t, keypair.Validate())
}

func TestParseOpensshPrivateKeyRawBinary(t *testing.T) {
	block, _ := pem.Decode([]byte(testOpenSSHPrivateKeyPEM))
	require.NotNil(t, block)

	keypair, err := ParseOpensshPrivateKeyRaw(block.Bytes)
	require.NoError(t, err)
	require.Len(t, keypair.public, ed25519PublicKeySize)
	require.Len(t, keypair.private, ed25519SeedSize)
}
