package auth

import (
	"context"
	"crypto/rand"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/rotisserie/eris"
)

func RunClient(ctx context.Context, conn BoundFramer, cfg ClientConfig) (ClientResult, error) {
	ctx = normalizeContext(ctx)
	if conn == nil {
		return ClientResult{}, eris.New("auth connection is required")
	}
	if err := cfg.Validate(); err != nil {
		return ClientResult{}, eris.Wrap(err, "validate client auth config")
	}

	machine := newAuthMachine("client", conn, cfg.Logger)
	return machine.authenticateClient(ctx, cfg)
}

func (m *authMachine) authenticateClient(ctx context.Context, cfg ClientConfig) (ClientResult, error) {
	m.debug("starting client authentication", "reference_identity", cfg.ReferenceIdentity, "username", cfg.Username)

	clientNonce, err := randomBytes(NonceSize)
	if err != nil {
		return ClientResult{}, eris.Wrap(err, "generate client nonce")
	}

	hostAuthInit := &authpb.HostAuthInit{
		MygoshAuthVersion: ProtocolVersion,
		ClientNonce:       clientNonce,
		ReferenceIdentity: cfg.ReferenceIdentity,
	}
	hostAuthInitHash, err := HashHostAuthInit(hostAuthInit)
	if err != nil {
		return ClientResult{}, eris.Wrap(err, "hash host auth init")
	}

	if err := sendAuthFrame(m.conn, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_HostAuthInit{
			HostAuthInit: hostAuthInit,
		},
	}); err != nil {
		return ClientResult{}, eris.Wrap(err, "send host auth init")
	}
	if err := m.advance(authStateNoiseEstablished, authStateHostAuthInitSent); err != nil {
		return ClientResult{}, err
	}

	serverAuth, err := receiveServerAuth(m.conn)
	if err != nil {
		return ClientResult{}, err
	}
	if err := m.advance(authStateHostAuthInitSent, authStateServerAuthRecv); err != nil {
		return ClientResult{}, err
	}

	serverHostKey, err := keys.ParsePublicKey(serverAuth.GetServerHostKey())
	if err != nil {
		return ClientResult{}, eris.Wrap(err, "parse server host key")
	}
	if err := serverHostKey.Validate(); err != nil {
		return ClientResult{}, eris.Wrap(err, "validate server host key")
	}

	serverAuthPayload, err := (ServerAuthToSign{
		ChannelBinding:   m.channelBinding,
		HostAuthInitHash: hostAuthInitHash,
		ServerHostKey:    serverAuth.GetServerHostKey(),
		ServerNonce:      serverAuth.GetServerNonce(),
	}).MarshalBinary()
	if err != nil {
		return ClientResult{}, eris.Wrap(err, "encode server auth payload")
	}
	if !(&serverHostKey).Verify(serverAuthPayload, serverAuth.GetSignature()) {
		return ClientResult{}, eris.New("server auth signature verification failed")
	}
	err = cfg.VerifyServerHostKey.VerifyHostKey(ctx, HostKeyVerificationRequest{
		ReferenceIdentity: cfg.ReferenceIdentity,
		HostKey:           serverHostKey.Clone(),
	})
	if err != nil {
		return ClientResult{}, eris.Wrap(err, "verify server host key")
	}
	m.debug("verified server host key", "reference_identity", cfg.ReferenceIdentity, "fingerprint", serverHostKey.FingerprintSHA256())

	serverAuthHash, err := HashServerAuthMessage(serverAuth)
	if err != nil {
		return ClientResult{}, eris.Wrap(err, "hash server auth")
	}

	clientKey, err := cfg.ClientIdentityProvider.ClientIdentity(ctx, ClientIdentityRequest{
		ReferenceIdentity: cfg.ReferenceIdentity,
		Username:          cfg.Username,
		ServerHostKey:     serverHostKey.Clone(),
	})
	if err != nil {
		return ClientResult{}, eris.Wrap(err, "select client identity")
	}
	if err := clientKey.Validate(); err != nil {
		return ClientResult{}, eris.Wrap(err, "validate client identity")
	}

	clientPublicKey := clientKey.PublicKey()
	clientPublicKeyBlob, err := clientPublicKey.MarshalBinary()
	if err != nil {
		return ClientResult{}, eris.Wrap(err, "encode client public key")
	}

	clientAuthPayload, err := (ClientAuthToSign{
		ChannelBinding:        m.channelBinding,
		HostAuthInitHash:      hostAuthInitHash,
		ServerAuthHash:        serverAuthHash,
		Username:              cfg.Username,
		ClientPublicKeyOrCert: clientPublicKeyBlob,
		ClientSigAlg:          string(clientPublicKey.Algorithm),
	}).MarshalBinary()
	if err != nil {
		return ClientResult{}, eris.Wrap(err, "encode client auth payload")
	}

	signature := (&clientKey).Sign(clientAuthPayload)

	clientAuthRequest := &authpb.ClientAuthRequest{
		Username:              cfg.Username,
		ClientPublicKeyOrCert: clientPublicKeyBlob,
		ClientSigAlg:          string(clientPublicKey.Algorithm),
		Signature:             signature,
	}

	if err := sendAuthFrame(m.conn, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_ClientAuthRequest{
			ClientAuthRequest: clientAuthRequest,
		},
	}); err != nil {
		return ClientResult{}, eris.Wrap(err, "send client auth request")
	}
	if err := m.advance(authStateServerAuthRecv, authStateClientAuthSent); err != nil {
		return ClientResult{}, err
	}

	response, err := receiveClientAuthResponse(m.conn)
	if err != nil {
		return ClientResult{}, err
	}
	if reject := response.GetReject(); reject != nil {
		return ClientResult{}, eris.Errorf("server rejected client auth: %s", reject.GetMessage())
	}
	if err := m.advance(authStateClientAuthSent, authStateAuthenticated); err != nil {
		return ClientResult{}, err
	}
	m.debug("client authentication complete", "reference_identity", cfg.ReferenceIdentity, "server_fingerprint", serverHostKey.FingerprintSHA256())

	return ClientResult{
		ReferenceIdentity: cfg.ReferenceIdentity,
		ServerHostKey:     serverHostKey.Clone(),
		ClientIdentity:    ClientIdentity{Username: cfg.Username, PublicKey: clientPublicKey.Clone()},
	}, nil
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}
