package session

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
	"github.com/stretchr/testify/require"
)

func TestConnectAcceptAuthenticatesSession(t *testing.T) {
	serverHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)

	serverSessionCh := make(chan *Session, 1)
	errs := make(chan error, 2)
	go func() {
		session, err := Accept(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
			AuthorizeClient: func(identity auth.ClientIdentity) error {
				if identity.Username != "alice" {
					return eris.Errorf("unexpected username %q", identity.Username)
				}
				expectedPublicKey := clientIdentity.PublicKey()
				if identity.PublicKey.Algorithm != expectedPublicKey.Algorithm || !bytes.Equal(identity.PublicKey.Bytes, expectedPublicKey.Bytes) {
					return eris.New("unexpected client public key")
				}
				return nil
			},
		})
		if err == nil {
			serverSessionCh <- session
		}
		errs <- err
	}()

	clientSession, err := Connect(context.Background(), clientConn, ClientConfig{
		ReferenceIdentity:   "server.example.test",
		Username:            "alice",
		ClientIdentity:      clientIdentity,
		VerifyServerHostKey: auth.ExactHostKeyVerifier("server.example.test", serverHostKey.PublicKey()),
	})
	require.NoError(t, err)
	require.NoError(t, <-errs)

	serverSession := <-serverSessionCh
	require.Equal(t, RoleClient, clientSession.Role())
	require.Equal(t, RoleServer, serverSession.Role())
	require.Equal(t, "server.example.test", clientSession.Metadata().ReferenceIdentity)
	require.Equal(t, serverHostKey.PublicKey(), clientSession.Metadata().ServerHostKey)
	require.Equal(t, "server.example.test", serverSession.Metadata().ReferenceIdentity)
	require.Equal(t, "alice", serverSession.Metadata().ClientIdentity.Username)
	require.Equal(t, clientIdentity.PublicKey(), serverSession.Metadata().ClientIdentity.PublicKey)
}

func TestConnectRejectsUnexpectedHostKey(t *testing.T) {
	serverHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	untrustedHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)

	errs := make(chan error, 1)
	go func() {
		_, err := Accept(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
			AuthorizeClient: func(identity auth.ClientIdentity) error {
				return nil
			},
		})
		errs <- err
	}()

	_, err = Connect(context.Background(), clientConn, ClientConfig{
		ReferenceIdentity:   "server.example.test",
		Username:            "alice",
		ClientIdentity:      clientIdentity,
		VerifyServerHostKey: auth.ExactHostKeyVerifier("server.example.test", untrustedHostKey.PublicKey()),
	})
	require.ErrorContains(t, err, "verify server host key")

	require.NoError(t, clientConn.Close())
	require.Error(t, <-errs)
}

func TestConnectReportsClientAuthRejection(t *testing.T) {
	serverHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)

	errs := make(chan error, 1)
	go func() {
		_, err := Accept(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
			AuthorizeClient: func(identity auth.ClientIdentity) error {
				return eris.New("client not authorized")
			},
		})
		errs <- err
	}()

	_, err = Connect(context.Background(), clientConn, ClientConfig{
		ReferenceIdentity:   "server.example.test",
		Username:            "alice",
		ClientIdentity:      clientIdentity,
		VerifyServerHostKey: auth.ExactHostKeyVerifier("server.example.test", serverHostKey.PublicKey()),
	})
	require.ErrorContains(t, err, "server rejected client auth")
	require.ErrorContains(t, err, "client not authorized")
	require.ErrorContains(t, <-errs, "authorize client")
}

func TestConnectRespectsContextCancellation(t *testing.T) {
	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)
	_ = serverConn

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := Connect(ctx, clientConn, ClientConfig{
			ReferenceIdentity: "server.example.test",
			Username:          "alice",
			ClientIdentity:    clientIdentity,
			VerifyServerHostKey: func(referenceIdentity string, hostKey keys.PublicKey) error {
				return nil
			},
		})
		errCh <- err
	}()

	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client establishment cancellation")
	}
}

func TestResolveTimeoutUsesDefault(t *testing.T) {
	require.Equal(t, defaultHandshakeTimeout, resolveTimeout(0, defaultHandshakeTimeout))
	require.Equal(t, defaultAuthTimeout, resolveTimeout(0, defaultAuthTimeout))
}

func TestConnectHandshakeTimeout(t *testing.T) {
	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)
	_ = serverConn

	errCh := make(chan error, 1)
	go func() {
		_, err := Connect(context.Background(), clientConn, ClientConfig{
			ReferenceIdentity:   "server.example.test",
			Username:            "alice",
			ClientIdentity:      clientIdentity,
			VerifyServerHostKey: func(referenceIdentity string, hostKey keys.PublicKey) error { return nil },
			HandshakeTimeout:    25 * time.Millisecond,
		})
		errCh <- err
	}()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handshake timeout")
	}
}

func TestConnectAuthTimeout(t *testing.T) {
	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)

	serverErrCh := make(chan error, 1)
	go func() {
		_, err := transport.HandshakeServer(serverConn)
		serverErrCh <- err
	}()

	_, err = Connect(context.Background(), clientConn, ClientConfig{
		ReferenceIdentity:   "server.example.test",
		Username:            "alice",
		ClientIdentity:      clientIdentity,
		VerifyServerHostKey: func(referenceIdentity string, hostKey keys.PublicKey) error { return nil },
		AuthTimeout:         25 * time.Millisecond,
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, <-serverErrCh)
}

func TestConnectContextCancellationBeatsPhaseTimeout(t *testing.T) {
	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)
	_ = serverConn

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := Connect(ctx, clientConn, ClientConfig{
			ReferenceIdentity:   "server.example.test",
			Username:            "alice",
			ClientIdentity:      clientIdentity,
			VerifyServerHostKey: func(referenceIdentity string, hostKey keys.PublicKey) error { return nil },
			HandshakeTimeout:    200 * time.Millisecond,
		})
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for context cancellation")
	}
}

func TestSessionRunRejectsPostAuthProtocol(t *testing.T) {
	serverHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)

	serverSessionCh := make(chan *Session, 1)
	errs := make(chan error, 2)
	go func() {
		session, err := Accept(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
			AuthorizeClient: func(identity auth.ClientIdentity) error {
				return nil
			},
		})
		if err == nil {
			serverSessionCh <- session
		}
		errs <- err
	}()

	clientSession, err := Connect(context.Background(), clientConn, ClientConfig{
		ReferenceIdentity:   "server.example.test",
		Username:            "alice",
		ClientIdentity:      clientIdentity,
		VerifyServerHostKey: auth.ExactHostKeyVerifier("server.example.test", serverHostKey.PublicKey()),
	})
	require.NoError(t, err)
	require.NoError(t, <-errs)

	serverSession := <-serverSessionCh
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- clientSession.Run(context.Background())
	}()

	errs = make(chan error, 1)
	go func() {
		errs <- transport.SendProto(serverSession.transport, &sessionpb.Envelope{
			Kind: &sessionpb.Envelope_Data{
				Data: &sessionpb.Data{Data: []byte("unsupported")},
			},
		})
	}()

	require.NoError(t, <-errs)
	require.ErrorContains(t, <-runErrCh, "session protocol not implemented")
}

func sessionPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	deadline := time.Now().Add(2 * time.Second)
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))

	return clientConn, serverConn
}
