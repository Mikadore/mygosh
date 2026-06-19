package session

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/stretchr/testify/require"
)

func TestSessionOpenChannelRequiresRun(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

	_, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.ErrorIs(t, err, errSessionNotRunning)

	_, err = clientSession.SendGlobalRequest(context.Background(), "keepalive", nil, true)
	require.ErrorIs(t, err, errSessionNotRunning)
}

func TestSessionWaitUntilRunning(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})
	defer serverSession.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, clientSession.WaitUntilRunning(ctx), context.DeadlineExceeded)

	run := startSessionRun(t, clientSession, nil)
	require.NoError(t, clientSession.WaitUntilRunning(context.Background()))
	stopSessionRun(t, run)
}

func TestSessionNilHandlerRejectsIncomingOpen(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})

	clientRun := startSessionRun(t, clientSession, nil)
	serverRun := startSessionRun(t, serverSession, nil)

	_, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.ErrorContains(t, err, "channel open rejected")

	stopSessionRun(t, clientRun)
	stopSessionRun(t, serverRun)
}

func TestSessionOpenChannelPreservesFrameBoundaries(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})

	serverChannels := make(chan *Channel, 1)
	clientRun := startSessionRun(t, clientSession, nil)
	serverRun := startSessionRun(t, serverSession, testHandler{
		onChannelOpen: func(_ context.Context, ch *Channel, req ChannelOpenRequest) ChannelOpenDecision {
			require.Equal(t, "session", req.Type)
			serverChannels <- ch
			return ChannelOpenDecision{OK: true}
		},
	})

	clientChannel, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)

	serverChannel := <-serverChannels

	require.NoError(t, clientChannel.Send(context.Background(), []byte("frame-1")))
	require.NoError(t, clientChannel.Send(context.Background(), []byte("frame-2")))

	frame, err := serverChannel.Recv(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("frame-1"), frame)

	frame, err = serverChannel.Recv(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("frame-2"), frame)

	stopSessionRun(t, clientRun)
	stopSessionRun(t, serverRun)
}

func TestSessionSendRejectsOversizedFrames(t *testing.T) {
	cfg := Config{
		InitialWindow:         32,
		MaxPacketSize:         4,
		WindowAdjustThreshold: 4,
	}
	clientSession, serverSession := authenticatedSessionPair(t, cfg)

	serverChannels := make(chan *Channel, 1)
	clientRun := startSessionRun(t, clientSession, nil)
	serverRun := startSessionRun(t, serverSession, testHandler{
		onChannelOpen: func(_ context.Context, ch *Channel, _ ChannelOpenRequest) ChannelOpenDecision {
			serverChannels <- ch
			return ChannelOpenDecision{OK: true}
		},
	})

	clientChannel, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	_ = <-serverChannels

	err = clientChannel.Send(context.Background(), []byte("hello"))
	require.ErrorContains(t, err, "exceeds remote max packet size")

	stopSessionRun(t, clientRun)
	stopSessionRun(t, serverRun)
}

func TestSessionChannelRequestRoundTripsPayload(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})

	clientRun := startSessionRun(t, clientSession, nil)
	serverRun := startSessionRun(t, serverSession, testHandler{
		onChannelOpen: func(_ context.Context, ch *Channel, _ ChannelOpenRequest) ChannelOpenDecision {
			return ChannelOpenDecision{
				OK: true,
				Handler: testChannelHandler{
					onRequest: func(_ context.Context, _ *Channel, req ChannelRequest) ChannelResponse {
						require.Equal(t, "exec", req.Type)
						require.Equal(t, []byte("payload"), req.Payload)
						return ChannelResponse{
							OK:      true,
							Payload: []byte("payload"),
						}
					},
				},
			}
		},
	})

	clientChannel, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)

	response, err := clientChannel.SendRequest(context.Background(), "exec", []byte("payload"), true)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.True(t, response.OK)
	require.Equal(t, []byte("payload"), response.Payload)

	stopSessionRun(t, clientRun)
	stopSessionRun(t, serverRun)
}

func TestLocallyOpenedChannelReceivesRequests(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})

	serverChannels := make(chan *Channel, 1)
	clientRequests := make(chan ChannelRequest, 1)
	clientRun := startSessionRun(t, clientSession, nil)
	serverRun := startSessionRun(t, serverSession, testHandler{
		onChannelOpen: func(_ context.Context, ch *Channel, _ ChannelOpenRequest) ChannelOpenDecision {
			serverChannels <- ch
			return ChannelOpenDecision{OK: true}
		},
	})

	_, err := clientSession.OpenChannelWithHandler(context.Background(), "session", nil, testChannelHandler{
		onRequest: func(_ context.Context, _ *Channel, req ChannelRequest) ChannelResponse {
			clientRequests <- req
			return ChannelResponse{OK: true}
		},
	})
	require.NoError(t, err)

	serverChannel := <-serverChannels
	response, err := serverChannel.SendRequest(context.Background(), "exit-status", []byte("status"), true)
	require.NoError(t, err)
	require.True(t, response.OK)

	req := <-clientRequests
	require.Equal(t, "exit-status", req.Type)
	require.Equal(t, []byte("status"), req.Payload)

	stopSessionRun(t, clientRun)
	stopSessionRun(t, serverRun)
}

func TestSessionChannelDataPreservesTerminalBytes(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})

	serverChannels := make(chan *Channel, 1)
	clientRun := startSessionRun(t, clientSession, nil)
	serverRun := startSessionRun(t, serverSession, testHandler{
		onChannelOpen: func(_ context.Context, ch *Channel, _ ChannelOpenRequest) ChannelOpenDecision {
			serverChannels <- ch
			return ChannelOpenDecision{OK: true}
		},
	})

	clientChannel, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	serverChannel := <-serverChannels

	terminalBytes := []byte{0x00, '\r', '\n', 0x1b, '[', '3', '1', 'm', 0xff}
	require.NoError(t, clientChannel.Send(context.Background(), terminalBytes))

	got, err := serverChannel.Recv(context.Background())
	require.NoError(t, err)
	require.Equal(t, terminalBytes, got)

	stopSessionRun(t, clientRun)
	stopSessionRun(t, serverRun)
}

func TestSessionGlobalRequestRoundTripsPayload(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})

	clientRun := startSessionRun(t, clientSession, nil)
	serverRun := startSessionRun(t, serverSession, testHandler{
		onGlobalRequest: func(_ context.Context, req GlobalRequest) GlobalResponse {
			require.Equal(t, "keepalive", req.Type)
			require.Equal(t, []byte("ping"), req.Payload)
			return GlobalResponse{
				OK:      true,
				Payload: []byte("ping"),
			}
		},
	})

	response, err := clientSession.SendGlobalRequest(context.Background(), "keepalive", []byte("ping"), true)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.True(t, response.OK)
	require.Equal(t, []byte("ping"), response.Payload)

	stopSessionRun(t, clientRun)
	stopSessionRun(t, serverRun)
}

func TestSessionSendBlocksUntilWindowAdjust(t *testing.T) {
	cfg := Config{
		InitialWindow:         4,
		MaxPacketSize:         4,
		WindowAdjustThreshold: 1,
	}
	clientSession, serverSession := authenticatedSessionPair(t, cfg)

	serverChannels := make(chan *Channel, 1)
	clientRun := startSessionRun(t, clientSession, nil)
	serverRun := startSessionRun(t, serverSession, testHandler{
		onChannelOpen: func(_ context.Context, ch *Channel, _ ChannelOpenRequest) ChannelOpenDecision {
			serverChannels <- ch
			return ChannelOpenDecision{OK: true}
		},
	})

	clientChannel, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	serverChannel := <-serverChannels

	require.NoError(t, clientChannel.Send(context.Background(), []byte("abcd")))

	secondSend := make(chan error, 1)
	go func() {
		secondSend <- clientChannel.Send(context.Background(), []byte("e"))
	}()

	select {
	case err := <-secondSend:
		t.Fatalf("second send completed before window adjust: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	frame, err := serverChannel.Recv(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("abcd"), frame)

	require.NoError(t, <-secondSend)

	frame, err = serverChannel.Recv(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("e"), frame)

	stopSessionRun(t, clientRun)
	stopSessionRun(t, serverRun)
}

func TestSessionRunRejectsUnknownChannelData(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})

	clientRun := startSessionRun(t, clientSession, nil)
	defer serverSession.Close() //nolint:errcheck

	require.NoError(t, transport.SendProto(serverSession.conn, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelData{
			ChannelData: &sessionpb.ChannelData{
				RecipientChannelId: 99,
				Data:               []byte("unexpected"),
			},
		},
	}))

	require.ErrorContains(t, <-clientRun.errCh, "unknown channel 99")
}

func TestSessionRunCanOnlyStartOnce(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})
	defer serverSession.Close() //nolint:errcheck

	run := startSessionRun(t, clientSession, nil)
	err := clientSession.Run(context.Background(), nil)
	require.ErrorIs(t, err, errSessionRunStarted)

	stopSessionRun(t, run)
}

func TestSessionCloseIsIdempotent(t *testing.T) {
	clientSession, serverSession := authenticatedSessionPair(t, Config{})
	clientRun := startSessionRun(t, clientSession, nil)
	serverRun := startSessionRun(t, serverSession, nil)

	require.NoError(t, clientSession.Close())
	require.NoError(t, clientSession.Close())

	stopSessionRun(t, clientRun)
	stopSessionRun(t, serverRun)
}

type testHandler struct {
	onChannelOpen   func(ctx context.Context, ch *Channel, req ChannelOpenRequest) ChannelOpenDecision
	onGlobalRequest func(ctx context.Context, req GlobalRequest) GlobalResponse
	onDisconnect    func(ctx context.Context, err error)
}

func (h testHandler) OnChannelOpen(ctx context.Context, ch *Channel, req ChannelOpenRequest) ChannelOpenDecision {
	if h.onChannelOpen != nil {
		return h.onChannelOpen(ctx, ch, req)
	}
	return ChannelOpenDecision{
		Code:    "unsupported-channel-open",
		Message: "incoming channel opens are not supported",
	}
}

func (h testHandler) OnGlobalRequest(ctx context.Context, req GlobalRequest) GlobalResponse {
	if h.onGlobalRequest != nil {
		return h.onGlobalRequest(ctx, req)
	}
	return GlobalResponse{
		Code:    "unsupported-global-request",
		Message: "global requests are not supported",
	}
}

func (h testHandler) OnDisconnect(ctx context.Context, err error) {
	if h.onDisconnect != nil {
		h.onDisconnect(ctx, err)
	}
}

type testChannelHandler struct {
	onRequest func(ctx context.Context, ch *Channel, req ChannelRequest) ChannelResponse
	onEOF     func(ctx context.Context, ch *Channel)
	onClose   func(ctx context.Context, ch *Channel)
}

func (h testChannelHandler) OnRequest(ctx context.Context, ch *Channel, req ChannelRequest) ChannelResponse {
	if h.onRequest != nil {
		return h.onRequest(ctx, ch, req)
	}
	return ChannelResponse{
		Code:    "unsupported-channel-request",
		Message: "channel requests are not supported",
	}
}

func (h testChannelHandler) OnEOF(ctx context.Context, ch *Channel) {
	if h.onEOF != nil {
		h.onEOF(ctx, ch)
	}
}

func (h testChannelHandler) OnClose(ctx context.Context, ch *Channel) {
	if h.onClose != nil {
		h.onClose(ctx, ch)
	}
}

func authenticatedSessionPair(t *testing.T, cfg Config) (*Session, *Session) {
	t.Helper()

	clientConn, serverConn := sessionPipe(t)

	serverSessionCh := make(chan *Session, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		secureConn, err := transport.HandshakeServer(serverConn)
		if err != nil {
			serverErrCh <- err
			return
		}
		session, err := New(secureConn, cfg, Options{})
		if err == nil {
			serverSessionCh <- session
		}
		serverErrCh <- err
	}()

	secureConn, err := transport.HandshakeClient(clientConn)
	require.NoError(t, err)
	clientSession, err := New(secureConn, cfg, Options{})
	require.NoError(t, err)
	require.NoError(t, <-serverErrCh)

	return clientSession, <-serverSessionCh
}

type runningSession struct {
	sess   *Session
	cancel context.CancelFunc
	errCh  <-chan error
}

func startSessionRun(t *testing.T, sess *Session, handler Handler) runningSession {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(ctx, handler)
	}()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	require.NoError(t, sess.WaitUntilRunning(waitCtx))

	return runningSession{
		sess:   sess,
		cancel: cancel,
		errCh:  errCh,
	}
}

func stopSessionRun(t *testing.T, run runningSession) {
	t.Helper()

	run.cancel()
	require.NoError(t, run.sess.Close())

	select {
	case err := <-run.errCh:
		if err != nil {
			require.ErrorIs(t, err, context.Canceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for session run to stop")
	}
}

func sessionPipe(t *testing.T) (net.Conn, net.Conn) {
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
