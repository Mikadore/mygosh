package auth

import (
	"context"
	"sync"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

const authenticationFailed = "authentication-failed"

var ErrDecisionMade = eris.New("server auth decision already made")

// PendingServerAuth owns the final accept/reject wire response after the
// client's signature has been verified. It is safe for concurrent use, but
// exactly one decision can be attempted.
type PendingServerAuth struct {
	mu       sync.Mutex
	conn     transport.BoundFramer
	machine  *authMachine
	verified VerifiedClient
	decided  bool
}

func BeginServer(ctx context.Context, conn transport.BoundFramer, cfg ServerConfig) (*PendingServerAuth, error) {
	ctx = normalizeContext(ctx)
	if conn == nil {
		return nil, eris.New("auth connection is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate server auth config")
	}

	machine := newAuthMachine("server", conn, cfg.Logger)
	verified, err := machine.verifyClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &PendingServerAuth{
		conn:     conn,
		machine:  machine,
		verified: verified,
	}, nil
}

func (p *PendingServerAuth) VerifiedClient() VerifiedClient {
	if p == nil {
		return VerifiedClient{}
	}
	return VerifiedClient{
		hostIdentity:      p.verified.hostIdentity,
		requestedUsername: p.verified.requestedUsername,
		provenKey:         clonePublicKey(p.verified.provenKey),
		serverKey:         clonePublicKey(p.verified.serverKey),
	}
}

func (p *PendingServerAuth) Accept() error {
	if err := p.beginDecision(); err != nil {
		return err
	}
	if err := sendClientAuthOK(p.conn); err != nil {
		return eris.Wrap(err, "send client auth response")
	}
	if err := p.machine.advance(authStateClientAuthRecv, authStateAuthenticated); err != nil {
		return err
	}
	p.machine.debug(
		"client authentication accepted",
		"reference_identity", p.verified.hostIdentity,
		"username", p.verified.requestedUsername,
		"fingerprint", p.verified.provenKey.FingerprintSHA256(),
	)
	return nil
}

func (p *PendingServerAuth) Reject() error {
	if err := p.beginDecision(); err != nil {
		return err
	}
	if err := sendClientAuthReject(p.conn, authenticationFailed, "authentication failed"); err != nil {
		return eris.Wrap(err, "send client auth rejection")
	}
	p.machine.info(
		"client authentication rejected",
		"code", authenticationFailed,
		"username", p.verified.requestedUsername,
		"fingerprint", p.verified.provenKey.FingerprintSHA256(),
	)
	return nil
}

func (p *PendingServerAuth) beginDecision() error {
	if p == nil {
		return eris.New("pending server auth is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.decided {
		return ErrDecisionMade
	}
	p.decided = true
	return nil
}

func (m *authMachine) verifyClient(ctx context.Context, cfg ServerConfig) (VerifiedClient, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedClient{}, err
	}

	hostAuthInit, err := receiveHostAuthInit(m.conn)
	if err != nil {
		return VerifiedClient{}, err
	}
	m.debug("received host auth init", "reference_identity", hostAuthInit.GetReferenceIdentity())
	if err := m.advance(authStateNoiseEstablished, authStateHostAuthInitRecv); err != nil {
		return VerifiedClient{}, err
	}
	if hostAuthInit.GetMygoshAuthVersion() != ProtocolVersion {
		err := eris.Errorf("unsupported auth version %q", hostAuthInit.GetMygoshAuthVersion())
		m.info("rejecting host auth init", "code", "unsupported-auth-version", "reference_identity", hostAuthInit.GetReferenceIdentity(), "version", hostAuthInit.GetMygoshAuthVersion())
		sendAuthError(m.conn, "unsupported-auth-version", err.Error())
		return VerifiedClient{}, err
	}

	hostAuthInitHash, err := HashHostAuthInit(hostAuthInit)
	if err != nil {
		return VerifiedClient{}, eris.Wrap(err, "hash host auth init")
	}

	hostSigner, err := cfg.HostKeyProvider.HostSigner(ctx, HostKeyRequest{
		ReferenceIdentity: hostAuthInit.GetReferenceIdentity(),
	})
	if err != nil {
		sendAuthError(m.conn, "host-key-unavailable", "server host key unavailable")
		return VerifiedClient{}, eris.Wrap(err, "select server host key")
	}

	hostPublicKey := hostSigner.PublicKey()
	if !(&hostPublicKey).IsSigning() {
		err := eris.New("server host signer must expose an ed25519 signing key")
		sendAuthError(m.conn, "invalid-host-key", "server host key unavailable")
		return VerifiedClient{}, err
	}
	hostPublicKeyBlob, err := hostPublicKey.MarshalBinary()
	if err != nil {
		return VerifiedClient{}, eris.Wrap(err, "encode server host key")
	}

	serverNonce, err := randomBytes(NonceSize)
	if err != nil {
		return VerifiedClient{}, eris.Wrap(err, "generate server nonce")
	}

	serverAuthPayload, err := (ServerAuthToSign{
		ChannelBinding:   m.channelBinding,
		HostAuthInitHash: hostAuthInitHash,
		ServerHostKey:    hostPublicKeyBlob,
		ServerNonce:      serverNonce,
	}).MarshalBinary()
	if err != nil {
		return VerifiedClient{}, eris.Wrap(err, "encode server auth payload")
	}

	signature, err := hostSigner.Sign(ctx, serverAuthPayload)
	if err != nil {
		return VerifiedClient{}, eris.Wrap(err, "sign server auth payload")
	}

	serverAuthMsg := &authpb.ServerAuth{
		ServerHostKey: hostPublicKeyBlob,
		ServerNonce:   serverNonce,
		Signature:     signature,
	}
	if err := sendAuthFrame(m.conn, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_ServerAuth{
			ServerAuth: serverAuthMsg,
		},
	}); err != nil {
		return VerifiedClient{}, eris.Wrap(err, "send server auth")
	}
	if err := m.advance(authStateHostAuthInitRecv, authStateServerAuthSent); err != nil {
		return VerifiedClient{}, err
	}

	serverAuthHash, err := HashServerAuthMessage(serverAuthMsg)
	if err != nil {
		return VerifiedClient{}, eris.Wrap(err, "hash server auth")
	}

	clientAuthRequest, err := receiveClientAuthRequest(m.conn)
	if err != nil {
		return VerifiedClient{}, err
	}
	m.debug("received client auth request", "username", clientAuthRequest.GetUsername())
	if err := m.advance(authStateServerAuthSent, authStateClientAuthRecv); err != nil {
		return VerifiedClient{}, err
	}

	clientPublicKey, err := keys.ParsePublicKey(clientAuthRequest.GetClientPublicKeyOrCert())
	if err != nil {
		m.rejectInvalidClient(clientAuthRequest.GetUsername(), "invalid-client-key")
		return VerifiedClient{}, eris.Wrap(err, "parse client public key")
	}
	if !(&clientPublicKey).IsSigning() {
		err := eris.New("client public key must be an ed25519 signing key")
		m.rejectInvalidClient(clientAuthRequest.GetUsername(), "invalid-client-key")
		return VerifiedClient{}, err
	}
	if clientAuthRequest.GetClientSigAlg() != string(clientPublicKey.Algorithm) {
		err := eris.Errorf("client signature algorithm %q does not match key algorithm %q", clientAuthRequest.GetClientSigAlg(), clientPublicKey.Algorithm)
		m.rejectInvalidClient(clientAuthRequest.GetUsername(), "invalid-client-sig-alg")
		return VerifiedClient{}, err
	}

	clientAuthPayload, err := (ClientAuthToSign{
		ChannelBinding:        m.channelBinding,
		HostAuthInitHash:      hostAuthInitHash,
		ServerAuthHash:        serverAuthHash,
		Username:              clientAuthRequest.GetUsername(),
		ClientPublicKeyOrCert: clientAuthRequest.GetClientPublicKeyOrCert(),
		ClientSigAlg:          clientAuthRequest.GetClientSigAlg(),
	}).MarshalBinary()
	if err != nil {
		m.rejectInvalidClient(clientAuthRequest.GetUsername(), "invalid-client-auth")
		return VerifiedClient{}, eris.Wrap(err, "encode client auth payload")
	}
	if !(&clientPublicKey).Verify(clientAuthPayload, clientAuthRequest.GetSignature()) {
		err := eris.New("client auth signature verification failed")
		m.rejectInvalidClient(clientAuthRequest.GetUsername(), "invalid-client-signature")
		return VerifiedClient{}, err
	}

	verified, err := NewVerifiedClient(
		hostAuthInit.GetReferenceIdentity(),
		clientAuthRequest.GetUsername(),
		clientPublicKey,
		hostPublicKey,
	)
	if err != nil {
		m.rejectInvalidClient(clientAuthRequest.GetUsername(), "invalid-verified-client")
		return VerifiedClient{}, eris.Wrap(err, "construct verified client")
	}
	m.debug(
		"client cryptographic proof verified",
		"reference_identity", verified.hostIdentity,
		"username", verified.requestedUsername,
		"fingerprint", verified.provenKey.FingerprintSHA256(),
	)
	return verified, nil
}

func (m *authMachine) rejectInvalidClient(username string, localCode string) {
	m.info("rejecting invalid client auth", "code", localCode, "username", username)
	_ = sendClientAuthReject(m.conn, authenticationFailed, "authentication failed")
}
