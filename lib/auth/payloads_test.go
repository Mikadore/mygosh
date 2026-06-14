package auth

import (
	"testing"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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

	expected, err := proto.MarshalOptions{Deterministic: true}.Marshal(&authpb.ServerAuthToSign{
		Context:          ServerAuthContext,
		ChannelBinding:   payload.ChannelBinding,
		HostAuthInitHash: payload.HostAuthInitHash,
		ServerHostKey:    payload.ServerHostKey,
		ServerNonce:      payload.ServerNonce,
	})
	require.NoError(t, err)
	require.Equal(t, expected, encoded)
}

func TestClientAuthToSignMarshalBinary(t *testing.T) {
	payload := ClientAuthToSign{
		ChannelBinding:        repeatedByte(0x11),
		HostAuthInitHash:      repeatedByte(0x22),
		ServerAuthHash:        repeatedByte(0x44),
		Username:              "alice",
		ClientPublicKeyOrCert: []byte("client-key"),
		ClientSigAlg:          "ed25519",
	}

	encoded, err := payload.MarshalBinary()
	require.NoError(t, err)

	expected, err := proto.MarshalOptions{Deterministic: true}.Marshal(&authpb.ClientAuthToSign{
		Context:               ClientAuthContext,
		ChannelBinding:        payload.ChannelBinding,
		HostAuthInitHash:      payload.HostAuthInitHash,
		ServerAuthHash:        payload.ServerAuthHash,
		Username:              payload.Username,
		ClientPublicKeyOrCert: payload.ClientPublicKeyOrCert,
		ClientSigAlg:          payload.ClientSigAlg,
	})
	require.NoError(t, err)
	require.Equal(t, expected, encoded)
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
		ClientPublicKeyOrCert: []byte("client-key"),
		ClientSigAlg:          "ed25519",
	}.Validate()
	require.ErrorContains(t, err, "server auth hash length")

	err = ClientAuthToSign{
		ChannelBinding:   repeatedByte(0x11),
		HostAuthInitHash: repeatedByte(0x22),
		ServerAuthHash:   repeatedByte(0x44),
		Username:         "alice",
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
