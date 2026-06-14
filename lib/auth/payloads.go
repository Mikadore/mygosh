package auth

import (
	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/rotisserie/eris"
	"google.golang.org/protobuf/proto"
)

const (
	ProtocolVersion   = "mygosh-auth-v1"
	ServerAuthContext = "mygosh-server-auth-to-sign-v1"
	ClientAuthContext = "mygosh-client-auth-to-sign-v1"
	DigestSize        = 32
	NonceSize         = 32
)

type ServerAuthToSign struct {
	ChannelBinding   []byte
	HostAuthInitHash []byte
	ServerHostKey    []byte
	ServerNonce      []byte
}

func (p ServerAuthToSign) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	packet, err := proto.MarshalOptions{Deterministic: true}.Marshal(&authpb.ServerAuthToSign{
		Context:          ServerAuthContext,
		ChannelBinding:   cloneBytes(p.ChannelBinding),
		HostAuthInitHash: cloneBytes(p.HostAuthInitHash),
		ServerHostKey:    cloneBytes(p.ServerHostKey),
		ServerNonce:      cloneBytes(p.ServerNonce),
	})
	if err != nil {
		return nil, eris.Wrap(err, "marshal server auth payload")
	}
	return packet, nil
}

func (p ServerAuthToSign) Validate() error {
	if err := validateDigest("channel binding", p.ChannelBinding); err != nil {
		return err
	}
	if err := validateDigest("host auth init hash", p.HostAuthInitHash); err != nil {
		return err
	}
	if len(p.ServerHostKey) == 0 {
		return eris.New("server host key is required")
	}
	if err := validateBytesLen("server nonce", p.ServerNonce, NonceSize); err != nil {
		return err
	}
	return nil
}

type ClientAuthToSign struct {
	ChannelBinding        []byte
	HostAuthInitHash      []byte
	ServerAuthHash        []byte
	Username              string
	ClientPublicKeyOrCert []byte
	ClientSigAlg          string
}

func (p ClientAuthToSign) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	packet, err := proto.MarshalOptions{Deterministic: true}.Marshal(&authpb.ClientAuthToSign{
		Context:               ClientAuthContext,
		ChannelBinding:        cloneBytes(p.ChannelBinding),
		HostAuthInitHash:      cloneBytes(p.HostAuthInitHash),
		ServerAuthHash:        cloneBytes(p.ServerAuthHash),
		Username:              p.Username,
		ClientPublicKeyOrCert: cloneBytes(p.ClientPublicKeyOrCert),
		ClientSigAlg:          p.ClientSigAlg,
	})
	if err != nil {
		return nil, eris.Wrap(err, "marshal client auth payload")
	}
	return packet, nil
}

func (p ClientAuthToSign) Validate() error {
	if err := validateDigest("channel binding", p.ChannelBinding); err != nil {
		return err
	}
	if err := validateDigest("host auth init hash", p.HostAuthInitHash); err != nil {
		return err
	}
	if err := validateDigest("server auth hash", p.ServerAuthHash); err != nil {
		return err
	}
	if p.Username == "" {
		return eris.New("username is required")
	}
	if len(p.ClientPublicKeyOrCert) == 0 {
		return eris.New("client public key or cert is required")
	}
	if p.ClientSigAlg == "" {
		return eris.New("client signature algorithm is required")
	}
	return nil
}

func validateDigest(label string, b []byte) error {
	return validateBytesLen(label, b, DigestSize)
}

func validateBytesLen(label string, b []byte, want int) error {
	if len(b) != want {
		return eris.Errorf("%s length %d does not match expected length %d", label, len(b), want)
	}
	return nil
}
