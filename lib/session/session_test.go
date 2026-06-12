package session

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/rotisserie/eris"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestEstablishClientServerSession(t *testing.T) {
	serverHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)

	serverSessionCh := make(chan *Session, 1)
	errs := make(chan error, 2)
	go func() {
		session, err := EstablishServer(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
			AuthorizeClient: func(principal ClientPrincipal) error {
				if principal.Username != "alice" {
					return eris.Errorf("unexpected username %q", principal.Username)
				}
				if principal.Service != "shell" {
					return eris.Errorf("unexpected service %q", principal.Service)
				}
				expectedPublicKey := clientIdentity.PublicKey()
				if principal.PublicKey.Algorithm != expectedPublicKey.Algorithm || !bytes.Equal(principal.PublicKey.Bytes, expectedPublicKey.Bytes) {
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

	clientSession, err := EstablishClient(context.Background(), clientConn, ClientConfig{
		ReferenceIdentity:   "server.example.test",
		Username:            "alice",
		Service:             "shell",
		ClientIdentity:      clientIdentity,
		VerifyServerHostKey: ExactHostKeyVerifier("server.example.test", serverHostKey.PublicKey()),
	})
	require.NoError(t, err)
	require.NoError(t, <-errs)

	serverSession := <-serverSessionCh
	require.Equal(t, RoleClient, clientSession.Role())
	require.Equal(t, RoleServer, serverSession.Role())
	require.Equal(t, "server.example.test", clientSession.Metadata().ReferenceIdentity)
	require.Equal(t, serverHostKey.PublicKey(), clientSession.Metadata().ServerHostKey)
	require.Equal(t, "server.example.test", serverSession.Metadata().ReferenceIdentity)
	require.Equal(t, clientIdentity.PublicKey(), serverSession.Metadata().ClientPrincipal.PublicKey)

	expected := &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_Data{
			Data: &sessionpb.Data{Data: []byte("authenticated transport")},
		},
	}

	gotCh := make(chan *sessionpb.Envelope, 1)
	errs = make(chan error, 2)
	go func() {
		got, err := serverSession.Transport().Receive()
		if err == nil {
			gotCh <- got
		}
		errs <- err
	}()
	go func() {
		errs <- clientSession.Transport().Send(expected)
	}()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	require.True(t, proto.Equal(expected, <-gotCh))
}

func TestEstablishClientRejectsUnexpectedHostKey(t *testing.T) {
	serverHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	untrustedHostKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)

	errs := make(chan error, 1)
	go func() {
		_, err := EstablishServer(context.Background(), serverConn, ServerConfig{
			HostKey: serverHostKey,
			AuthorizeClient: func(principal ClientPrincipal) error {
				return nil
			},
		})
		errs <- err
	}()

	_, err = EstablishClient(context.Background(), clientConn, ClientConfig{
		ReferenceIdentity:   "server.example.test",
		Username:            "alice",
		Service:             "shell",
		ClientIdentity:      clientIdentity,
		VerifyServerHostKey: ExactHostKeyVerifier("server.example.test", untrustedHostKey.PublicKey()),
	})
	require.ErrorContains(t, err, "verify server host key")

	require.NoError(t, clientConn.Close())
	require.Error(t, <-errs)
}

func TestEstablishClientRespectsContextCancellation(t *testing.T) {
	clientIdentity, err := keys.GenerateEd25519()
	require.NoError(t, err)

	clientConn, serverConn := sessionPipe(t)
	_ = serverConn

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := EstablishClient(ctx, clientConn, ClientConfig{
			ReferenceIdentity: "server.example.test",
			Username:          "alice",
			Service:           "shell",
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
