package auth

import (
	"bytes"
	"crypto/rand"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

type HostKeyVerifier func(referenceIdentity string, hostKey keys.PublicKey) error

type AuthorizeClientFunc func(identity ClientIdentity) error

type ClientConfig struct {
	ReferenceIdentity   string
	Username            string
	ClientIdentity      keys.Keypair
	VerifyServerHostKey HostKeyVerifier
}

func (c ClientConfig) Validate() error {
	if c.ReferenceIdentity == "" {
		return eris.New("reference identity is required")
	}
	if c.Username == "" {
		return eris.New("username is required")
	}
	if !(&c.ClientIdentity).IsSigning() {
		return eris.New("client identity must be an ed25519 signing key")
	}
	if c.VerifyServerHostKey == nil {
		return eris.New("server host key verifier is required")
	}
	return nil
}

type ServerConfig struct {
	HostKey         keys.Keypair
	AuthorizeClient AuthorizeClientFunc
}

func (c ServerConfig) Validate() error {
	if !(&c.HostKey).IsSigning() {
		return eris.New("server host key must be an ed25519 signing key")
	}
	if c.AuthorizeClient == nil {
		return eris.New("client authorizer is required")
	}
	return nil
}

type ClientIdentity struct {
	Username  string
	PublicKey keys.PublicKey
}

type Result struct {
	ReferenceIdentity string
	ServerHostKey     keys.PublicKey
	ClientIdentity    ClientIdentity
}

func AuthenticateClient(messageTransport *transport.Transport, channelBinding []byte, cfg ClientConfig) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, eris.Wrap(err, "validate client auth config")
	}

	machine := newAuthMachine("client", messageTransport, channelBinding)
	return machine.authenticateClient(cfg)
}

func AuthenticateServer(messageTransport *transport.Transport, channelBinding []byte, cfg ServerConfig) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, eris.Wrap(err, "validate server auth config")
	}

	machine := newAuthMachine("server", messageTransport, channelBinding)
	return machine.authenticateServer(cfg)
}

type authState string

const (
	authStateNoiseEstablished authState = "noise-established"
	authStateHostAuthInitSent authState = "host-auth-init-sent"
	authStateHostAuthInitRecv authState = "host-auth-init-received"
	authStateServerAuthSent   authState = "server-auth-sent"
	authStateServerAuthRecv   authState = "server-auth-received"
	authStateClientAuthSent   authState = "client-auth-sent"
	authStateClientAuthRecv   authState = "client-auth-received"
	authStateAuthenticated    authState = "authenticated"
)

type authMachine struct {
	role           string
	state          authState
	transport      *transport.Transport
	channelBinding []byte
}

func newAuthMachine(role string, messageTransport *transport.Transport, channelBinding []byte) *authMachine {
	return &authMachine{
		role:           role,
		state:          authStateNoiseEstablished,
		transport:      messageTransport,
		channelBinding: cloneBytes(channelBinding),
	}
}

func (m *authMachine) advance(expected authState, next authState) error {
	if m.state != expected {
		return eris.Errorf("%s auth state %q cannot transition to %q", m.role, m.state, next)
	}
	m.state = next
	return nil
}

func (m *authMachine) authenticateClient(cfg ClientConfig) (Result, error) {
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
	if err := cfg.VerifyServerHostKey(cfg.ReferenceIdentity, serverHostKey); err != nil {
		return Result{}, eris.Wrap(err, "verify server host key")
	}

	serverAuthHash, err := HashServerAuthMessage(serverAuth)
	if err != nil {
		return Result{}, eris.Wrap(err, "hash server auth")
	}

	clientPublicKeyBlob, err := cfg.ClientIdentity.PublicKey().MarshalBinary()
	if err != nil {
		return Result{}, eris.Wrap(err, "encode client public key")
	}

	clientAuthPayload, err := (ClientAuthToSign{
		ChannelBinding:        m.channelBinding,
		HostAuthInitHash:      hostAuthInitHash,
		ServerAuthHash:        serverAuthHash,
		Username:              cfg.Username,
		ClientPublicKeyOrCert: clientPublicKeyBlob,
		ClientSigAlg:          string(cfg.ClientIdentity.Algorithm),
	}).MarshalBinary()
	if err != nil {
		return Result{}, eris.Wrap(err, "encode client auth payload")
	}

	clientAuthRequest := &authpb.ClientAuthRequest{
		Username:              cfg.Username,
		ClientPublicKeyOrCert: clientPublicKeyBlob,
		ClientSigAlg:          string(cfg.ClientIdentity.Algorithm),
		Signature:             (&cfg.ClientIdentity).Sign(clientAuthPayload),
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

	return Result{
		ReferenceIdentity: cfg.ReferenceIdentity,
		ServerHostKey:     clonePublicKey(serverHostKey),
	}, nil
}

func (m *authMachine) authenticateServer(cfg ServerConfig) (Result, error) {
	hostAuthInit, err := receiveHostAuthInit(m.transport)
	if err != nil {
		return Result{}, err
	}
	if err := m.advance(authStateNoiseEstablished, authStateHostAuthInitRecv); err != nil {
		return Result{}, err
	}
	if hostAuthInit.GetMygoshAuthVersion() != ProtocolVersion {
		err := eris.Errorf("unsupported auth version %q", hostAuthInit.GetMygoshAuthVersion())
		sendAuthError(m.transport, "unsupported-auth-version", err.Error())
		return Result{}, err
	}

	hostAuthInitHash, err := HashHostAuthInit(hostAuthInit)
	if err != nil {
		return Result{}, eris.Wrap(err, "hash host auth init")
	}

	hostPublicKey := cfg.HostKey.PublicKey()
	hostPublicKeyBlob, err := hostPublicKey.MarshalBinary()
	if err != nil {
		return Result{}, eris.Wrap(err, "encode server host key")
	}

	serverNonce, err := randomBytes(NonceSize)
	if err != nil {
		return Result{}, eris.Wrap(err, "generate server nonce")
	}

	serverAuthPayload, err := (ServerAuthToSign{
		ChannelBinding:   m.channelBinding,
		HostAuthInitHash: hostAuthInitHash,
		ServerHostKey:    hostPublicKeyBlob,
		ServerNonce:      serverNonce,
	}).MarshalBinary()
	if err != nil {
		return Result{}, eris.Wrap(err, "encode server auth payload")
	}

	serverAuthMsg := &authpb.ServerAuth{
		ServerHostKey: hostPublicKeyBlob,
		ServerNonce:   serverNonce,
		Signature:     (&cfg.HostKey).Sign(serverAuthPayload),
	}
	if err := sendAuthFrame(m.transport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_ServerAuth{
			ServerAuth: serverAuthMsg,
		},
	}); err != nil {
		return Result{}, eris.Wrap(err, "send server auth")
	}
	if err := m.advance(authStateHostAuthInitRecv, authStateServerAuthSent); err != nil {
		return Result{}, err
	}

	serverAuthHash, err := HashServerAuthMessage(serverAuthMsg)
	if err != nil {
		return Result{}, eris.Wrap(err, "hash server auth")
	}

	clientAuthRequest, err := receiveClientAuthRequest(m.transport)
	if err != nil {
		return Result{}, err
	}
	if err := m.advance(authStateServerAuthSent, authStateClientAuthRecv); err != nil {
		return Result{}, err
	}

	clientPublicKey, err := keys.ParsePublicKey(clientAuthRequest.GetClientPublicKeyOrCert())
	if err != nil {
		sendClientAuthReject(m.transport, "invalid-client-key", "invalid client public key")
		return Result{}, eris.Wrap(err, "parse client public key")
	}
	if !(&clientPublicKey).IsSigning() {
		err := eris.New("client public key must be an ed25519 signing key")
		sendClientAuthReject(m.transport, "invalid-client-key", err.Error())
		return Result{}, err
	}
	if clientAuthRequest.GetClientSigAlg() != string(clientPublicKey.Algorithm) {
		err := eris.Errorf("client signature algorithm %q does not match key algorithm %q", clientAuthRequest.GetClientSigAlg(), clientPublicKey.Algorithm)
		sendClientAuthReject(m.transport, "invalid-client-sig-alg", err.Error())
		return Result{}, err
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
		sendClientAuthReject(m.transport, "invalid-client-auth", "failed to encode client auth payload")
		return Result{}, eris.Wrap(err, "encode client auth payload")
	}
	if !(&clientPublicKey).Verify(clientAuthPayload, clientAuthRequest.GetSignature()) {
		err := eris.New("client auth signature verification failed")
		sendClientAuthReject(m.transport, "invalid-client-signature", err.Error())
		return Result{}, err
	}

	clientIdentity := ClientIdentity{
		Username:  clientAuthRequest.GetUsername(),
		PublicKey: clonePublicKey(clientPublicKey),
	}
	if err := cfg.AuthorizeClient(clientIdentity); err != nil {
		sendClientAuthReject(m.transport, "unauthorized-client", err.Error())
		return Result{}, eris.Wrap(err, "authorize client")
	}

	if err := sendClientAuthOK(m.transport); err != nil {
		return Result{}, eris.Wrap(err, "send client auth response")
	}
	if err := m.advance(authStateClientAuthRecv, authStateAuthenticated); err != nil {
		return Result{}, err
	}

	return Result{
		ReferenceIdentity: hostAuthInit.GetReferenceIdentity(),
		ServerHostKey:     clonePublicKey(hostPublicKey),
		ClientIdentity:    clientIdentity,
	}, nil
}

func receiveHostAuthInit(messageTransport *transport.Transport) (*authpb.HostAuthInit, error) {
	frame, err := receiveAuthFrame(messageTransport)
	if err != nil {
		return nil, eris.Wrap(err, "receive host auth init")
	}

	switch kind := frame.Kind.(type) {
	case *authpb.AuthFrame_HostAuthInit:
		return kind.HostAuthInit, nil
	case *authpb.AuthFrame_Error:
		return nil, eris.Errorf("peer rejected auth: %s", kind.Error.GetMessage())
	default:
		return nil, eris.Errorf("expected host auth init, got %T", kind)
	}
}

func receiveServerAuth(messageTransport *transport.Transport) (*authpb.ServerAuth, error) {
	frame, err := receiveAuthFrame(messageTransport)
	if err != nil {
		return nil, eris.Wrap(err, "receive server auth")
	}

	switch kind := frame.Kind.(type) {
	case *authpb.AuthFrame_ServerAuth:
		return kind.ServerAuth, nil
	case *authpb.AuthFrame_Error:
		return nil, eris.Errorf("server rejected auth: %s", kind.Error.GetMessage())
	default:
		return nil, eris.Errorf("expected server auth, got %T", kind)
	}
}

func receiveClientAuthRequest(messageTransport *transport.Transport) (*authpb.ClientAuthRequest, error) {
	frame, err := receiveAuthFrame(messageTransport)
	if err != nil {
		return nil, eris.Wrap(err, "receive client auth request")
	}

	switch kind := frame.Kind.(type) {
	case *authpb.AuthFrame_ClientAuthRequest:
		return kind.ClientAuthRequest, nil
	case *authpb.AuthFrame_Error:
		return nil, eris.Errorf("peer rejected auth: %s", kind.Error.GetMessage())
	default:
		return nil, eris.Errorf("expected client auth request, got %T", kind)
	}
}

func receiveClientAuthResponse(messageTransport *transport.Transport) (*authpb.ClientAuthResponse, error) {
	frame, err := receiveAuthFrame(messageTransport)
	if err != nil {
		return nil, eris.Wrap(err, "receive client auth response")
	}

	switch kind := frame.Kind.(type) {
	case *authpb.AuthFrame_ClientAuthResponse:
		return kind.ClientAuthResponse, nil
	case *authpb.AuthFrame_Error:
		return nil, eris.Errorf("server rejected auth: %s", kind.Error.GetMessage())
	default:
		return nil, eris.Errorf("expected client auth response, got %T", kind)
	}
}

func receiveAuthFrame(messageTransport *transport.Transport) (*authpb.AuthFrame, error) {
	var frame authpb.AuthFrame
	if err := transport.ReceiveProto(messageTransport, &frame); err != nil {
		return nil, eris.Wrap(err, "receive auth frame")
	}
	return &frame, nil
}

func sendAuthFrame(messageTransport *transport.Transport, frame *authpb.AuthFrame) error {
	return transport.SendProto(messageTransport, frame)
}

func sendAuthError(messageTransport *transport.Transport, code string, message string) {
	_ = sendAuthFrame(messageTransport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_Error{
			Error: &authpb.AuthError{
				Code:    code,
				Message: message,
			},
		},
	})
}

func sendClientAuthOK(messageTransport *transport.Transport) error {
	return sendAuthFrame(messageTransport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_ClientAuthResponse{
			ClientAuthResponse: &authpb.ClientAuthResponse{
				Result: &authpb.ClientAuthResponse_Ok{
					Ok: &authpb.AuthSuccess{},
				},
			},
		},
	})
}

func sendClientAuthReject(messageTransport *transport.Transport, code string, message string) {
	_ = sendAuthFrame(messageTransport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_ClientAuthResponse{
			ClientAuthResponse: &authpb.ClientAuthResponse{
				Result: &authpb.ClientAuthResponse_Reject{
					Reject: &authpb.AuthReject{
						Code:    code,
						Message: message,
					},
				},
			},
		},
	})
}

func ExactHostKeyVerifier(referenceIdentity string, expected keys.PublicKey) HostKeyVerifier {
	expected = clonePublicKey(expected)
	return func(actualReferenceIdentity string, actualHostKey keys.PublicKey) error {
		if actualReferenceIdentity != referenceIdentity {
			return eris.Errorf("reference identity %q does not match expected %q", actualReferenceIdentity, referenceIdentity)
		}
		if actualHostKey.Algorithm != expected.Algorithm || !bytes.Equal(actualHostKey.Bytes, expected.Bytes) {
			return eris.Errorf("unexpected host key fingerprint %s", actualHostKey.FingerprintSHA256())
		}
		return nil
	}
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func clonePublicKey(key keys.PublicKey) keys.PublicKey {
	return keys.PublicKey{
		Algorithm: key.Algorithm,
		Bytes:     cloneBytes(key.Bytes),
	}
}
