package auth

import (
	"context"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

func RunServer(ctx context.Context, conn transport.BoundFramer, cfg ServerConfig) (ServerResult, error) {
	ctx = normalizeContext(ctx)
	if conn == nil {
		return ServerResult{}, eris.New("auth connection is required")
	}
	if err := cfg.Validate(); err != nil {
		return ServerResult{}, eris.Wrap(err, "validate server auth config")
	}

	machine := newAuthMachine("server", conn, cfg.Logger)
	return machine.authenticateServer(ctx, cfg)
}

func (m *authMachine) authenticateServer(ctx context.Context, cfg ServerConfig) (ServerResult, error) {
	hostAuthInit, err := receiveHostAuthInit(m.conn)
	if err != nil {
		return ServerResult{}, err
	}
	m.debug("received host auth init", "reference_identity", hostAuthInit.GetReferenceIdentity())
	if err := m.advance(authStateNoiseEstablished, authStateHostAuthInitRecv); err != nil {
		return ServerResult{}, err
	}
	if hostAuthInit.GetMygoshAuthVersion() != ProtocolVersion {
		err := eris.Errorf("unsupported auth version %q", hostAuthInit.GetMygoshAuthVersion())
		m.info("rejecting host auth init", "code", "unsupported-auth-version", "reference_identity", hostAuthInit.GetReferenceIdentity(), "version", hostAuthInit.GetMygoshAuthVersion())
		sendAuthError(m.conn, "unsupported-auth-version", err.Error())
		return ServerResult{}, err
	}

	hostAuthInitHash, err := HashHostAuthInit(hostAuthInit)
	if err != nil {
		return ServerResult{}, eris.Wrap(err, "hash host auth init")
	}

	hostSigner, err := cfg.HostKeyProvider.HostSigner(ctx, HostKeyRequest{
		ReferenceIdentity: hostAuthInit.GetReferenceIdentity(),
	})
	if err != nil {
		sendAuthError(m.conn, "host-key-unavailable", err.Error())
		return ServerResult{}, eris.Wrap(err, "select server host key")
	}

	hostPublicKey := hostSigner.PublicKey()
	if !(&hostPublicKey).IsSigning() {
		err := eris.New("server host signer must expose an ed25519 signing key")
		sendAuthError(m.conn, "invalid-host-key", err.Error())
		return ServerResult{}, err
	}
	hostPublicKeyBlob, err := hostPublicKey.MarshalBinary()
	if err != nil {
		return ServerResult{}, eris.Wrap(err, "encode server host key")
	}

	serverNonce, err := randomBytes(NonceSize)
	if err != nil {
		return ServerResult{}, eris.Wrap(err, "generate server nonce")
	}

	serverAuthPayload, err := (ServerAuthToSign{
		ChannelBinding:   m.channelBinding,
		HostAuthInitHash: hostAuthInitHash,
		ServerHostKey:    hostPublicKeyBlob,
		ServerNonce:      serverNonce,
	}).MarshalBinary()
	if err != nil {
		return ServerResult{}, eris.Wrap(err, "encode server auth payload")
	}

	signature, err := hostSigner.Sign(ctx, serverAuthPayload)
	if err != nil {
		return ServerResult{}, eris.Wrap(err, "sign server auth payload")
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
		return ServerResult{}, eris.Wrap(err, "send server auth")
	}
	if err := m.advance(authStateHostAuthInitRecv, authStateServerAuthSent); err != nil {
		return ServerResult{}, err
	}

	serverAuthHash, err := HashServerAuthMessage(serverAuthMsg)
	if err != nil {
		return ServerResult{}, eris.Wrap(err, "hash server auth")
	}

	clientAuthRequest, err := receiveClientAuthRequest(m.conn)
	if err != nil {
		return ServerResult{}, err
	}
	m.debug("received client auth request", "username", clientAuthRequest.GetUsername())
	if err := m.advance(authStateServerAuthSent, authStateClientAuthRecv); err != nil {
		return ServerResult{}, err
	}

	clientPublicKey, err := keys.ParsePublicKey(clientAuthRequest.GetClientPublicKeyOrCert())
	if err != nil {
		m.info("rejecting client auth", "code", "invalid-client-key", "username", clientAuthRequest.GetUsername())
		sendClientAuthReject(m.conn, "invalid-client-key", "invalid client public key")
		return ServerResult{}, eris.Wrap(err, "parse client public key")
	}
	if !(&clientPublicKey).IsSigning() {
		err := eris.New("client public key must be an ed25519 signing key")
		m.info("rejecting client auth", "code", "invalid-client-key", "username", clientAuthRequest.GetUsername(), "algorithm", clientPublicKey.Algorithm)
		sendClientAuthReject(m.conn, "invalid-client-key", err.Error())
		return ServerResult{}, err
	}
	if clientAuthRequest.GetClientSigAlg() != string(clientPublicKey.Algorithm) {
		err := eris.Errorf("client signature algorithm %q does not match key algorithm %q", clientAuthRequest.GetClientSigAlg(), clientPublicKey.Algorithm)
		m.info("rejecting client auth", "code", "invalid-client-sig-alg", "username", clientAuthRequest.GetUsername(), "client_sig_alg", clientAuthRequest.GetClientSigAlg(), "key_algorithm", clientPublicKey.Algorithm)
		sendClientAuthReject(m.conn, "invalid-client-sig-alg", err.Error())
		return ServerResult{}, err
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
		m.info("rejecting client auth", "code", "invalid-client-auth", "username", clientAuthRequest.GetUsername())
		sendClientAuthReject(m.conn, "invalid-client-auth", "failed to encode client auth payload")
		return ServerResult{}, eris.Wrap(err, "encode client auth payload")
	}
	if !(&clientPublicKey).Verify(clientAuthPayload, clientAuthRequest.GetSignature()) {
		err := eris.New("client auth signature verification failed")
		m.info("rejecting client auth", "code", "invalid-client-signature", "username", clientAuthRequest.GetUsername(), "fingerprint", clientPublicKey.FingerprintSHA256())
		sendClientAuthReject(m.conn, "invalid-client-signature", err.Error())
		return ServerResult{}, err
	}

	clientIdentity := ClientIdentity{
		Username:  clientAuthRequest.GetUsername(),
		PublicKey: clonePublicKey(clientPublicKey),
	}
	clientKeyAuthorization, err := cfg.AuthorizeClientKey.AuthorizeClientKey(ctx, ClientKeyAuthorizationRequest{
		ReferenceIdentity: hostAuthInit.GetReferenceIdentity(),
		ServerHostKey:     clonePublicKey(hostPublicKey),
		Identity:          clientIdentity,
	})
	if err != nil {
		m.info("rejecting client auth", "code", "unauthorized-client", "username", clientIdentity.Username, "fingerprint", clientIdentity.PublicKey.FingerprintSHA256())
		sendClientAuthReject(m.conn, "unauthorized-client", err.Error())
		return ServerResult{}, eris.Wrap(err, "authorize client")
	}

	if err := sendClientAuthOK(m.conn); err != nil {
		return ServerResult{}, eris.Wrap(err, "send client auth response")
	}
	if err := m.advance(authStateClientAuthRecv, authStateAuthenticated); err != nil {
		return ServerResult{}, err
	}
	m.debug("client authentication complete", "reference_identity", hostAuthInit.GetReferenceIdentity(), "username", clientIdentity.Username, "fingerprint", clientIdentity.PublicKey.FingerprintSHA256())

	return ServerResult{
		ReferenceIdentity:      hostAuthInit.GetReferenceIdentity(),
		ServerHostKey:          clonePublicKey(hostPublicKey),
		ClientIdentity:         clientIdentity,
		ClientKeyAuthorization: clientKeyAuthorization,
	}, nil
}
