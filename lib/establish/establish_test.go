package establish

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/stretchr/testify/require"
)

func TestBeginAcceptWaitsForDecisionAndAccepts(t *testing.T) {
	serverHostKey, clientIdentity, clientConn, serverConn := establishmentFixture(t)

	pendingCh := make(chan *PendingServer, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		pending, err := BeginAccept(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
		})
		if err == nil {
			pendingCh <- pending
		}
		serverErrCh <- err
	}()

	clientCh := make(chan *Client, 1)
	clientErrCh := make(chan error, 1)
	go func() {
		client, err := Connect(context.Background(), clientConn, ClientConfig{
			ReferenceIdentity:      "server.example.test",
			Username:               "alice",
			ClientIdentityProvider: auth.StaticClientIdentityProvider(clientIdentity),
			VerifyServerHostKey:    auth.ExactHostKeyVerifier("server.example.test", serverHostKey.PublicKey()),
		})
		if err == nil {
			clientCh <- client
		}
		clientErrCh <- err
	}()

	pending := <-pendingCh
	require.NoError(t, <-serverErrCh)
	require.Equal(t, "server.example.test", pending.VerifiedClient().HostIdentity())
	require.Equal(t, "alice", pending.VerifiedClient().RequestedUsername())
	require.Equal(t, clientIdentity.PublicKey(), pending.VerifiedClient().ProvenKey())

	select {
	case err := <-clientErrCh:
		t.Fatalf("client completed before server decision: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	server, err := pending.Accept()
	require.NoError(t, err)
	require.NotNil(t, server.Session)
	require.NoError(t, <-clientErrCh)
	client := <-clientCh
	require.Equal(t, serverHostKey.PublicKey(), client.Auth.ServerHostKey)

	require.ErrorIs(t, pending.Reject(), auth.ErrDecisionMade)
	require.NoError(t, client.Close())
	require.NoError(t, pending.Close())
}

func TestBeginAcceptRejectsGenerically(t *testing.T) {
	serverHostKey, clientIdentity, clientConn, serverConn := establishmentFixture(t)

	pendingCh := make(chan *PendingServer, 1)
	go func() {
		pending, err := BeginAccept(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
		})
		require.NoError(t, err)
		pendingCh <- pending
	}()

	clientErrCh := make(chan error, 1)
	go func() {
		_, err := Connect(context.Background(), clientConn, ClientConfig{
			ReferenceIdentity:      "server.example.test",
			Username:               "missing-local-user",
			ClientIdentityProvider: auth.StaticClientIdentityProvider(clientIdentity),
			VerifyServerHostKey:    auth.ExactHostKeyVerifier("server.example.test", serverHostKey.PublicKey()),
		})
		clientErrCh <- err
	}()

	pending := <-pendingCh
	require.NoError(t, pending.Reject())
	clientErr := <-clientErrCh
	require.ErrorContains(t, clientErr, "authentication failed")
	require.NotContains(t, clientErr.Error(), "missing-local-user")
	require.ErrorIs(t, pending.Reject(), auth.ErrDecisionMade)
}

func TestPendingCloseWithoutDecisionUnblocksClient(t *testing.T) {
	serverHostKey, clientIdentity, clientConn, serverConn := establishmentFixture(t)

	pendingCh := make(chan *PendingServer, 1)
	go func() {
		pending, err := BeginAccept(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
		})
		require.NoError(t, err)
		pendingCh <- pending
	}()

	clientErrCh := make(chan error, 1)
	go func() {
		_, err := Connect(context.Background(), clientConn, ClientConfig{
			ReferenceIdentity:      "server.example.test",
			Username:               "alice",
			ClientIdentityProvider: auth.StaticClientIdentityProvider(clientIdentity),
			VerifyServerHostKey:    auth.ExactHostKeyVerifier("server.example.test", serverHostKey.PublicKey()),
		})
		clientErrCh <- err
	}()

	pending := <-pendingCh
	require.NoError(t, pending.Close())
	require.Error(t, <-clientErrCh)
	_, err := pending.Accept()
	require.ErrorIs(t, err, auth.ErrDecisionMade)
}

func TestPendingAuthTimeoutIncludesApplicationPolicyDelay(t *testing.T) {
	serverHostKey, clientIdentity, clientConn, serverConn := establishmentFixture(t)

	pendingCh := make(chan *PendingServer, 1)
	go func() {
		pending, err := BeginAccept(context.Background(), serverConn, ServerConfig{
			HostKey:     serverHostKey,
			AuthTimeout: 75 * time.Millisecond,
		})
		require.NoError(t, err)
		pendingCh <- pending
	}()

	clientErrCh := make(chan error, 1)
	go func() {
		_, err := Connect(context.Background(), clientConn, ClientConfig{
			ReferenceIdentity:      "server.example.test",
			Username:               "alice",
			ClientIdentityProvider: auth.StaticClientIdentityProvider(clientIdentity),
			VerifyServerHostKey:    auth.ExactHostKeyVerifier("server.example.test", serverHostKey.PublicKey()),
		})
		clientErrCh <- err
	}()

	pending := <-pendingCh
	select {
	case <-pending.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pending auth deadline")
	}
	require.ErrorIs(t, context.Cause(pending.Context()), context.DeadlineExceeded)
	_, err := pending.Accept()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Error(t, <-clientErrCh)
}

func TestConnectRejectsUnexpectedHostKey(t *testing.T) {
	serverHostKey, clientIdentity, clientConn, serverConn := establishmentFixture(t)
	untrustedHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	serverErrCh := make(chan error, 1)
	go func() {
		_, err := BeginAccept(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
		})
		serverErrCh <- err
	}()

	_, err = Connect(context.Background(), clientConn, ClientConfig{
		ReferenceIdentity:      "server.example.test",
		Username:               "alice",
		ClientIdentityProvider: auth.StaticClientIdentityProvider(clientIdentity),
		VerifyServerHostKey:    auth.ExactHostKeyVerifier("server.example.test", untrustedHostKey.PublicKey()),
	})
	require.ErrorContains(t, err, "verify server host key")
	require.NoError(t, clientConn.Close())
	require.Error(t, <-serverErrCh)
}

func TestConnectContextCancellation(t *testing.T) {
	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)
	clientConn, _ := connectionPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := Connect(ctx, clientConn, ClientConfig{
			ReferenceIdentity:      "server.example.test",
			Username:               "alice",
			ClientIdentityProvider: auth.StaticClientIdentityProvider(clientIdentity),
			VerifyServerHostKey: auth.HostKeyVerifierFunc(func(context.Context, auth.HostKeyVerificationRequest) error {
				return nil
			}),
		})
		errCh <- err
	}()
	cancel()

	select {
	case err := <-errCh:
		require.True(t, errors.Is(err, context.Canceled))
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client cancellation")
	}
}

func TestResolveTimeoutUsesDefault(t *testing.T) {
	require.Equal(t, defaultHandshakeTimeout, resolveTimeout(0, defaultHandshakeTimeout))
	require.Equal(t, defaultAuthTimeout, resolveTimeout(0, defaultAuthTimeout))
}

func establishmentFixture(t *testing.T) (keys.Keypair, keys.Keypair, net.Conn, net.Conn) {
	t.Helper()
	serverHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)
	clientConn, serverConn := connectionPipe(t)
	return serverHostKey, clientIdentity, clientConn, serverConn
}

func connectionPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	deadline := time.Now().Add(10 * time.Second)
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))
	return clientConn, serverConn
}
