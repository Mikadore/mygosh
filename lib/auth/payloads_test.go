package auth

import (
	"testing"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/stretchr/testify/require"
)

func TestServerAuthToSignMarshalBinary(t *testing.T) {
	payload := ServerAuthToSign{
		ChannelBinding:   repeatedByte(0x11),
		HostAuthInitHash: repeatedByte(0x22),
		ServerHostKey:    []byte("server-host-key"),
		ServerNonce:      repeatedByte(0x33),
	}

	encoded, err := payload.MarshalBinary()
	require.NoError(t, err)

	dec := bincoder.NewCursor(encoded)
	require.Equal(t, ServerAuthContext, dec.UTF8String())
	require.Equal(t, payload.ChannelBinding, dec.Bytes())
	require.Equal(t, payload.HostAuthInitHash, dec.Bytes())
	require.Equal(t, payload.ServerHostKey, dec.Bytes())
	require.Equal(t, payload.ServerNonce, dec.Bytes())
	require.NoError(t, dec.Done())
}

func TestClientAuthToSignMarshalBinary(t *testing.T) {
	payload := ClientAuthToSign{
		ChannelBinding:        repeatedByte(0x11),
		HostAuthInitHash:      repeatedByte(0x22),
		ServerAuthHash:        repeatedByte(0x44),
		Username:              "alice",
		Service:               "shell",
		ClientPublicKeyOrCert: []byte("client-key"),
		ClientSigAlg:          "ed25519",
	}

	encoded, err := payload.MarshalBinary()
	require.NoError(t, err)

	dec := bincoder.NewCursor(encoded)
	require.Equal(t, ClientAuthContext, dec.UTF8String())
	require.Equal(t, payload.ChannelBinding, dec.Bytes())
	require.Equal(t, payload.HostAuthInitHash, dec.Bytes())
	require.Equal(t, payload.ServerAuthHash, dec.Bytes())
	require.Equal(t, payload.Username, dec.UTF8String())
	require.Equal(t, payload.Service, dec.UTF8String())
	require.Equal(t, payload.ClientPublicKeyOrCert, dec.Bytes())
	require.Equal(t, payload.ClientSigAlg, dec.UTF8String())
	require.NoError(t, dec.Done())
}

func TestServerAuthToSignValidateRejectsInvalidPayloads(t *testing.T) {
	err := ServerAuthToSign{
		ChannelBinding:   []byte("short"),
		HostAuthInitHash: repeatedByte(0x22),
		ServerHostKey:    []byte("server-host-key"),
		ServerNonce:      repeatedByte(0x33),
	}.Validate()
	require.ErrorContains(t, err, "channel binding length")

	err = ServerAuthToSign{
		ChannelBinding:   repeatedByte(0x11),
		HostAuthInitHash: repeatedByte(0x22),
		ServerNonce:      repeatedByte(0x33),
	}.Validate()
	require.ErrorContains(t, err, "server host key is required")
}

func TestClientAuthToSignValidateRejectsInvalidPayloads(t *testing.T) {
	err := ClientAuthToSign{
		ChannelBinding:        repeatedByte(0x11),
		HostAuthInitHash:      repeatedByte(0x22),
		ServerAuthHash:        []byte("short"),
		Username:              "alice",
		Service:               "shell",
		ClientPublicKeyOrCert: []byte("client-key"),
		ClientSigAlg:          "ed25519",
	}.Validate()
	require.ErrorContains(t, err, "server auth hash length")

	err = ClientAuthToSign{
		ChannelBinding:   repeatedByte(0x11),
		HostAuthInitHash: repeatedByte(0x22),
		ServerAuthHash:   repeatedByte(0x44),
		Username:         "alice",
		Service:          "shell",
		ClientSigAlg:     "ed25519",
	}.Validate()
	require.ErrorContains(t, err, "client public key or cert is required")
}

func repeatedByte(b byte) []byte {
	out := make([]byte, DigestSize)
	for i := range out {
		out[i] = b
	}
	return out
}
