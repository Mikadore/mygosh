package auth

import (
	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/rotisserie/eris"
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

	type canonicalServerAuthToSign struct {
		Context          string
		ChannelBinding   []byte
		HostAuthInitHash []byte
		ServerHostKey    []byte
		ServerNonce      []byte
	}

	return bincoder.Canonicalize(canonicalServerAuthToSign{
		Context:          ServerAuthContext,
		ChannelBinding:   p.ChannelBinding,
		HostAuthInitHash: p.HostAuthInitHash,
		ServerHostKey:    p.ServerHostKey,
		ServerNonce:      p.ServerNonce,
	})
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
	Service               string
	ClientPublicKeyOrCert []byte
	ClientSigAlg          string
}

func (p ClientAuthToSign) MarshalBinary() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	type canonicalClientAuthToSign struct {
		Context               string
		ChannelBinding        []byte
		HostAuthInitHash      []byte
		ServerAuthHash        []byte
		Username              string
		Service               string
		ClientPublicKeyOrCert []byte
		ClientSigAlg          string
	}

	return bincoder.Canonicalize(canonicalClientAuthToSign{
		Context:               ClientAuthContext,
		ChannelBinding:        p.ChannelBinding,
		HostAuthInitHash:      p.HostAuthInitHash,
		ServerAuthHash:        p.ServerAuthHash,
		Username:              p.Username,
		Service:               p.Service,
		ClientPublicKeyOrCert: p.ClientPublicKeyOrCert,
		ClientSigAlg:          p.ClientSigAlg,
	})
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
	if p.Service == "" {
		return eris.New("service is required")
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
