package auth

import (
	"context"
	"crypto/rand"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

func AuthenticateClient(ctx context.Context, messageTransport *transport.Transport, channelBinding []byte, cfg ClientConfig) (Result, error) {
	ctx = normalizeContext(ctx)
	if err := cfg.Validate(); err != nil {
		return Result{}, eris.Wrap(err, "validate client auth config")
	}

	machine := newAuthMachine("client", messageTransport, channelBinding, cfg.Logger)
	return machine.authenticateClient(ctx, cfg)
}

func (m *authMachine) authenticateClient(ctx context.Context, cfg ClientConfig) (Result, error) {
	m.debug("starting client authentication", "reference_identity", cfg.ReferenceIdentity, "username", cfg.Username)

	clientNonce, err := randomBytes(NonceSize)
	if err != nil {
		return Result{}, eris.Wrap(err, "generate client nonce")
	}

	hostAuthInit := &authpb.HostAuthInit{
		MygoshAuthVersion: ProtocolVersion,
		ClientNonce:       clientNonce,
		ReferenceIdentity: cfg.ReferenceIdentity,
	}
	hostAuthInitHash, err := HashHostAuthInit(hostAuthInit)
	if err != nil {
		return Result{}, eris.Wrap(err, "hash host auth init")
	}

	if err := sendAuthFrame(m.transport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_HostAuthInit{
			HostAuthInit: hostAuthInit,
		},
	}); err != nil {
		return Result{}, eris.Wrap(err, "send host auth init")
	}
	if err := m.advance(authStateNoiseEstablished, authStateHostAuthInitSent); err != nil {
		return Result{}, err
	}

	serverAuth, err := receiveServerAuth(m.transport)
	if err != nil {
		return Result{}, err
	}
	if err := m.advance(authStateHostAuthInitSent, authStateServerAuthRecv); err != nil {
		return Result{}, err
	}

	serverHostKey, err := keys.ParsePublicKey(serverAuth.GetServerHostKey())
	if err != nil {
		return Result{}, eris.Wrap(err, "parse server host key")
	}
	if !(&serverHostKey).IsSigning() {
		return Result{}, eris.New("server host key must be an ed25519 signing key")
	}

	serverAuthPayload, err := (ServerAuthToSign{
		ChannelBinding:   m.channelBinding,
		HostAuthInitHash: hostAuthInitHash,
		ServerHostKey:    serverAuth.GetServerHostKey(),
		ServerNonce:      serverAuth.GetServerNonce(),
	}).MarshalBinary()
	if err != nil {
		return Result{}, eris.Wrap(err, "encode server auth payload")
	}
	if !(&serverHostKey).Verify(serverAuthPayload, serverAuth.GetSignature()) {
		return Result{}, eris.New("server auth signature verification failed")
	}
	if err := cfg.VerifyServerHostKey.VerifyHostKey(ctx, HostKeyVerificationRequest{
		ReferenceIdentity: cfg.ReferenceIdentity,
		HostKey:           clonePublicKey(serverHostKey),
	}); err != nil {
		return Result{}, eris.Wrap(err, "verify server host key")
	}
	m.debug("verified server host key", "reference_identity", cfg.ReferenceIdentity, "fingerprint", serverHostKey.FingerprintSHA256())

	serverAuthHash, err := HashServerAuthMessage(serverAuth)
	if err != nil {
		return Result{}, eris.Wrap(err, "hash server auth")
	}

	clientPublicKey := cfg.ClientSigner.PublicKey()
	clientPublicKeyBlob, err := clientPublicKey.MarshalBinary()
	if err != nil {
		return Result{}, eris.Wrap(err, "encode client public key")
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
		return Result{}, eris.Wrap(err, "encode client auth payload")
	}

	signature, err := cfg.ClientSigner.Sign(ctx, clientAuthPayload)
	if err != nil {
		return Result{}, eris.Wrap(err, "sign client auth payload")
	}

	clientAuthRequest := &authpb.ClientAuthRequest{
		Username:              cfg.Username,
		ClientPublicKeyOrCert: clientPublicKeyBlob,
		ClientSigAlg:          string(clientPublicKey.Algorithm),
		Signature:             signature,
	}

	if err := sendAuthFrame(m.transport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_ClientAuthRequest{
			ClientAuthRequest: clientAuthRequest,
		},
	}); err != nil {
		return Result{}, eris.Wrap(err, "send client auth request")
	}
	if err := m.advance(authStateServerAuthRecv, authStateClientAuthSent); err != nil {
		return Result{}, err
	}

	response, err := receiveClientAuthResponse(m.transport)
	if err != nil {
		return Result{}, err
	}
	if reject := response.GetReject(); reject != nil {
		return Result{}, eris.Errorf("server rejected client auth: %s", reject.GetMessage())
	}
	if err := m.advance(authStateClientAuthSent, authStateAuthenticated); err != nil {
		return Result{}, err
	}
	m.debug("client authentication complete", "reference_identity", cfg.ReferenceIdentity, "server_fingerprint", serverHostKey.FingerprintSHA256())

	return Result{
		ReferenceIdentity: cfg.ReferenceIdentity,
		ServerHostKey:     clonePublicKey(serverHostKey),
	}, nil
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}
