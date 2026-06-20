package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	serverauthz "github.com/Mikadore/mygosh/app/server/authz"
	usermodel "github.com/Mikadore/mygosh/lib/account"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/service"
	"github.com/Mikadore/mygosh/lib/service/servicepb"
	sessionmux "github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

func TestShellChannelHandlerEnforcesRequestOrder(t *testing.T) {
	handler := newShellChannelHandler(context.Background(), "/bin/sh", currentAccount(t), nil, nil, func(error) {})

	execPayload := mustServicePayload(t, &servicepb.ExecRequest{Command: "true"})
	response := handler.OnRequest(context.Background(), nil, sessionmux.ChannelRequest{
		Type:    service.RequestTypeExec,
		Payload: execPayload,
	})
	require.False(t, response.OK)
	require.Equal(t, "invalid-request-order", response.Code)

	ptyPayload := mustServicePayload(t, &servicepb.PtyRequest{Term: "xterm", Rows: 24, Cols: 80})
	response = handler.OnRequest(context.Background(), nil, sessionmux.ChannelRequest{
		Type:    service.RequestTypePTY,
		Payload: ptyPayload,
	})
	require.True(t, response.OK)

	response = handler.OnRequest(context.Background(), nil, sessionmux.ChannelRequest{
		Type:    service.RequestTypePTY,
		Payload: ptyPayload,
	})
	require.False(t, response.OK)
	require.Equal(t, "invalid-request-order", response.Code)

	sizePayload := mustServicePayload(t, &servicepb.TerminalSize{Rows: 40, Cols: 120})
	response = handler.OnRequest(context.Background(), nil, sessionmux.ChannelRequest{
		Type:    service.RequestTypeWindowChange,
		Payload: sizePayload,
	})
	require.False(t, response.OK)
	require.Equal(t, "invalid-request-order", response.Code)
}

func TestShellChannelHandlerRejectsInvalidPTYAndFailedExec(t *testing.T) {
	handler := newShellChannelHandler(context.Background(), "/definitely/missing-mygosh-shell", currentAccount(t), nil, nil, func(error) {})

	invalidPTY, err := proto.Marshal(&servicepb.PtyRequest{})
	require.NoError(t, err)
	response := handler.OnRequest(context.Background(), nil, sessionmux.ChannelRequest{
		Type:    service.RequestTypePTY,
		Payload: invalidPTY,
	})
	require.False(t, response.OK)
	require.Equal(t, "invalid-pty-request", response.Code)

	ptyPayload := mustServicePayload(t, &servicepb.PtyRequest{Term: "xterm", Rows: 24, Cols: 80})
	response = handler.OnRequest(context.Background(), nil, sessionmux.ChannelRequest{
		Type:    service.RequestTypePTY,
		Payload: ptyPayload,
	})
	require.True(t, response.OK)

	execPayload := mustServicePayload(t, &servicepb.ExecRequest{Command: "true"})
	response = handler.OnRequest(context.Background(), nil, sessionmux.ChannelRequest{
		Type:    service.RequestTypeExec,
		Payload: execPayload,
	})
	require.False(t, response.OK)
	require.Equal(t, "exec-start-failed", response.Code)
}

func TestCommandCredentialUsesAuthorizedAccount(t *testing.T) {
	account := currentAccount(t)
	require.Nil(t, commandCredential(account))

	account.Id++
	account.PrimaryGroup.Id++
	account.SupplementaryGroups = []usermodel.Group{{Id: 17}, {Id: 23}}
	credential := commandCredential(account)
	require.NotNil(t, credential)
	require.Equal(t, account.Id, credential.Uid)
	require.Equal(t, account.PrimaryGroup.Id, credential.Gid)
	require.Equal(t, []uint32{17, 23}, credential.Groups)
}

func TestShellDemoRunsCommandOverSessionChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientSession, serverSession := sessionPair(t)
	account := currentAccount(t)
	lease := &shellTestLease{}
	authorization, credentials := shellAuthorization(t, account, lease)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- NewShellDemo(serverSession, "/bin/sh", credentials, authorization, nil).Run(ctx)
	}()

	clientRunErr := make(chan error, 1)
	go func() {
		clientRunErr <- clientSession.Run(ctx, nil)
	}()
	require.NoError(t, clientSession.WaitUntilRunning(ctx))

	exitHandler := &testExitStatusHandler{status: make(chan int32, 1)}
	channel, err := clientSession.OpenChannelWithHandler(ctx, service.ChannelTypeSession, nil, exitHandler)
	require.NoError(t, err)

	ptyResponse, err := channel.SendRequest(ctx, service.RequestTypePTY, mustServicePayload(t, &servicepb.PtyRequest{
		Term: "xterm",
		Rows: 24,
		Cols: 80,
	}), true)
	require.NoError(t, err)
	require.True(t, ptyResponse.OK)

	execResponse, err := channel.SendRequest(ctx, service.RequestTypeExec, mustServicePayload(t, &servicepb.ExecRequest{
		Command: "sleep 0.1; stty size; printf mygosh-terminal; exit 7",
	}), true)
	require.NoError(t, err)
	require.True(t, execResponse.OK)

	_, err = channel.SendRequest(ctx, service.RequestTypeWindowChange, mustServicePayload(t, &servicepb.TerminalSize{
		Rows: 40,
		Cols: 120,
	}), false)
	require.NoError(t, err)

	var output []byte
	for {
		frame, err := channel.Recv(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		output = append(output, frame...)
	}
	require.Contains(t, string(output), "40 120")
	require.Contains(t, string(output), "mygosh-terminal")
	require.Equal(t, int32(7), <-exitHandler.status)
	require.NoError(t, channel.Close())

	require.NoError(t, <-serverDone)
	require.Equal(t, int32(1), lease.closed.Load())
	clientErr := <-clientRunErr
	if clientErr != nil {
		require.ErrorIs(t, clientErr, context.Canceled)
	}
}

type shellTestLease struct {
	closed atomic.Int32
}

func (l *shellTestLease) Close() error {
	l.closed.Add(1)
	return nil
}

type testExitStatusHandler struct {
	once   sync.Once
	status chan int32
}

func (h *testExitStatusHandler) OnRequest(_ context.Context, _ *sessionmux.Channel, req sessionmux.ChannelRequest) sessionmux.ChannelResponse {
	if req.Type != service.RequestTypeExitStatus {
		return sessionmux.ChannelResponse{}
	}
	var status servicepb.ExitStatus
	if err := service.UnmarshalPayload(req.Payload, &status); err != nil {
		return sessionmux.ChannelResponse{}
	}
	h.once.Do(func() {
		h.status <- status.GetCode()
	})
	return sessionmux.ChannelResponse{OK: true}
}

func (*testExitStatusHandler) OnEOF(context.Context, *sessionmux.Channel)   {}
func (*testExitStatusHandler) OnClose(context.Context, *sessionmux.Channel) {}

func mustServicePayload(t *testing.T, message proto.Message) []byte {
	t.Helper()
	payload, err := service.MarshalPayload(message)
	require.NoError(t, err)
	return payload
}

func currentAccount(t *testing.T) usermodel.Account {
	t.Helper()
	current, err := osuser.Current()
	require.NoError(t, err)
	account, err := usermodel.LookupAccount(current.Username)
	require.NoError(t, err)
	require.Equal(t, uint32(os.Geteuid()), account.Id)
	require.Equal(t, uint32(os.Getegid()), account.PrimaryGroup.Id)
	return account
}

func shellAuthorization(t *testing.T, account usermodel.Account, lease serverauthz.SessionLease) (*serverauthz.Authz, serverauthz.ConnectionCredentials) {
	t.Helper()
	clientKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	serverKey, err := keys.GenerateEd25519()
	require.NoError(t, err)

	sshPublicKey, err := ssh.NewPublicKey(ed25519.PublicKey(clientKey.Public))
	require.NoError(t, err)
	line := sshPublicKey.Type() + " " + base64.StdEncoding.EncodeToString(sshPublicKey.Marshal()) + "\n"
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte(line), 0o600))

	authorization, err := serverauthz.New(serverauthz.Config{
		Resolver: usermodel.ResolverFunc(func(context.Context, string) (usermodel.Account, error) {
			return account, nil
		}),
		AuthorizedKeysPaths: []string{path},
		SessionPolicy: serverauthz.SessionPolicyFunc(func(context.Context, serverauthz.ConnectionCredentials, serverauthz.SessionRequest) (serverauthz.SessionLease, error) {
			return lease, nil
		}),
	})
	require.NoError(t, err)

	verified, err := auth.NewVerifiedClient("server.example.test", account.Username, clientKey.PublicKey(), serverKey.PublicKey())
	require.NoError(t, err)
	credentials, err := authorization.AuthorizeConnection(context.Background(), serverauthz.ConnectionRequest{VerifiedClient: verified})
	require.NoError(t, err)
	return authorization, credentials
}

func sessionPair(t *testing.T) (*sessionmux.Session, *sessionmux.Session) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	deadline := time.Now().Add(10 * time.Second)
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))

	serverSessionCh := make(chan *sessionmux.Session, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		secureConn, err := transport.HandshakeServer(serverConn)
		if err != nil {
			serverErrCh <- err
			return
		}
		sess, err := sessionmux.New(secureConn, sessionmux.Config{}, sessionmux.Options{})
		if err == nil {
			serverSessionCh <- sess
		}
		serverErrCh <- err
	}()

	secureConn, err := transport.HandshakeClient(clientConn)
	require.NoError(t, err)
	clientSession, err := sessionmux.New(secureConn, sessionmux.Config{}, sessionmux.Options{})
	require.NoError(t, err)
	require.NoError(t, <-serverErrCh)
	return clientSession, <-serverSessionCh
}
