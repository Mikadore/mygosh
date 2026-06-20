package session

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/stretchr/testify/require"
)

func TestSessionOpenChannelRequiresActivation(t *testing.T) {
	clientConn, serverConn := sessionPipe(t)

	serverReady := make(chan *Session, 1)
	go func() {
		secureConn, err := transport.HandshakeServer(serverConn)
		require.NoError(t, err)
		prepared, err := Prepare(Config{}, nil, Options{})
		require.NoError(t, err)
		sess, err := prepared.Bind(context.Background(), secureConn)
		require.NoError(t, err)
		serverReady <- sess
	}()

	secureConn, err := transport.HandshakeClient(clientConn)
	require.NoError(t, err)
	prepared, err := Prepare(Config{}, nil, Options{})
	require.NoError(t, err)
	clientSession, err := prepared.Bind(context.Background(), secureConn)
	require.NoError(t, err)
	serverSession := <-serverReady
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

	_, err = clientSession.OpenChannel(context.Background(), "session", nil)
	require.ErrorIs(t, err, errSessionNotActive)

	_, err = clientSession.SendGlobalRequest(context.Background(), "keepalive", nil, true)
	require.ErrorIs(t, err, errSessionNotActive)
}

func TestSessionNilHandlerRejectsIncomingOpenWhileActive(t *testing.T) {
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, nil)
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

	_, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.ErrorContains(t, err, "channel open rejected")

	select {
	case <-clientSession.Done():
		t.Fatal("client session closed after reject-all response")
	case <-serverSession.Done():
		t.Fatal("server session closed after reject-all response")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSessionOpenChannelPreservesFrameBoundaries(t *testing.T) {
	serverChannels := make(chan *Channel, 1)
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, testHandler{
		onChannelOpen: func(_ context.Context, req ChannelOpenRequest) ChannelOpenDecision {
			require.Equal(t, "session", req.Type)
			return ChannelOpenDecision{
				OK: true,
				Handler: testChannelHandler{
					onOpen: func(_ context.Context, ch *Channel) {
						serverChannels <- ch
					},
				},
			}
		},
	})
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

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
}

func TestRemoteClosePreservesAlreadyQueuedChannelData(t *testing.T) {
	serverChannels := make(chan *Channel, 1)
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, testHandler{
		onChannelOpen: func(_ context.Context, _ ChannelOpenRequest) ChannelOpenDecision {
			return ChannelOpenDecision{
				OK: true,
				Handler: testChannelHandler{
					onOpen: func(_ context.Context, ch *Channel) {
						serverChannels <- ch
					},
				},
			}
		},
	})
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

	clientChannel, err := clientSession.OpenChannel(context.Background(), "command", nil)
	require.NoError(t, err)
	serverChannel := <-serverChannels
	require.NoError(t, serverChannel.Send(context.Background(), []byte("terminal-frame")))
	require.NoError(t, serverChannel.Close())

	frame, err := clientChannel.Recv(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("terminal-frame"), frame)
	_, err = clientChannel.Recv(context.Background())
	require.ErrorIs(t, err, io.EOF)
}

func TestSessionChannelRequestRoundTripsPayload(t *testing.T) {
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, testHandler{
		onChannelOpen: func(_ context.Context, _ ChannelOpenRequest) ChannelOpenDecision {
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
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

	clientChannel, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)

	response, err := clientChannel.SendRequest(context.Background(), "exec", []byte("payload"), true)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.True(t, response.OK)
	require.Equal(t, []byte("payload"), response.Payload)
}

func TestLocallyOpenedChannelReceivesRequests(t *testing.T) {
	serverChannels := make(chan *Channel, 1)
	clientRequests := make(chan ChannelRequest, 1)
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, testHandler{
		onChannelOpen: func(_ context.Context, _ ChannelOpenRequest) ChannelOpenDecision {
			return ChannelOpenDecision{
				OK: true,
				Handler: testChannelHandler{
					onOpen: func(_ context.Context, ch *Channel) {
						serverChannels <- ch
					},
				},
			}
		},
	})
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

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
}

func TestSessionChannelDataPreservesTerminalBytes(t *testing.T) {
	serverChannels := make(chan *Channel, 1)
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, testHandler{
		onChannelOpen: func(_ context.Context, _ ChannelOpenRequest) ChannelOpenDecision {
			return ChannelOpenDecision{
				OK: true,
				Handler: testChannelHandler{
					onOpen: func(_ context.Context, ch *Channel) {
						serverChannels <- ch
					},
				},
			}
		},
	})
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

	clientChannel, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	serverChannel := <-serverChannels

	terminalBytes := []byte{0x00, '\r', '\n', 0x1b, '[', '3', '1', 'm', 0xff}
	require.NoError(t, clientChannel.Send(context.Background(), terminalBytes))

	got, err := serverChannel.Recv(context.Background())
	require.NoError(t, err)
	require.Equal(t, terminalBytes, got)
}

func TestSessionGlobalRequestRoundTripsPayload(t *testing.T) {
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, testHandler{
		onGlobalRequest: func(_ context.Context, req GlobalRequest) GlobalResponse {
			require.Equal(t, "keepalive", req.Type)
			require.Equal(t, []byte("ping"), req.Payload)
			return GlobalResponse{
				OK:      true,
				Payload: []byte("ping"),
			}
		},
	})
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

	response, err := clientSession.SendGlobalRequest(context.Background(), "keepalive", []byte("ping"), true)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.True(t, response.OK)
	require.Equal(t, []byte("ping"), response.Payload)
}

func TestSessionSendBlocksUntilWindowAdjust(t *testing.T) {
	cfg := Config{
		InitialWindow:         4,
		MaxPacketSize:         4,
		WindowAdjustThreshold: 1,
	}

	serverChannels := make(chan *Channel, 1)
	clientSession, serverSession := activatedSessionPair(t, cfg, nil, testHandler{
		onChannelOpen: func(_ context.Context, _ ChannelOpenRequest) ChannelOpenDecision {
			return ChannelOpenDecision{
				OK: true,
				Handler: testChannelHandler{
					onOpen: func(_ context.Context, ch *Channel) {
						serverChannels <- ch
					},
				},
			}
		},
	})
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

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
}

func TestSessionProtocolErrorClosesConnection(t *testing.T) {
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, nil)
	defer serverSession.Close() //nolint:errcheck

	require.NoError(t, wire.SendProto(serverSession.conn, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelData{
			ChannelData: &sessionpb.ChannelData{
				RecipientChannelId: 99,
				Data:               []byte("unexpected"),
			},
		},
	}))

	require.ErrorContains(t, clientSession.Wait(), "unknown channel 99")
}

func TestSessionHandlerQueueExhaustionClosesConnection(t *testing.T) {
	cfg := Config{Limits: Limits{MaxQueuedFramesPerChannel: 1}}
	serverChannels := make(chan *Channel, 1)
	blockRequests := make(chan struct{})
	requestStarted := make(chan struct{})
	var requestStartedOnce sync.Once
	clientSession, serverSession := activatedSessionPair(t, cfg, nil, testHandler{
		onChannelOpen: func(_ context.Context, _ ChannelOpenRequest) ChannelOpenDecision {
			return ChannelOpenDecision{
				OK: true,
				Handler: testChannelHandler{
					onOpen: func(_ context.Context, ch *Channel) {
						serverChannels <- ch
					},
					onRequest: func(_ context.Context, _ *Channel, _ ChannelRequest) ChannelResponse {
						requestStartedOnce.Do(func() {
							close(requestStarted)
						})
						<-blockRequests
						return ChannelResponse{OK: true}
					},
				},
			}
		},
	})
	defer clientSession.Close() //nolint:errcheck

	clientChannel, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	serverChannel := <-serverChannels

	_, err = clientChannel.SendRequest(context.Background(), "one", nil, false)
	require.NoError(t, err)
	<-requestStarted
	_, err = clientChannel.SendRequest(context.Background(), "two", nil, false)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		serverChannel.mu.Lock()
		defer serverChannel.mu.Unlock()
		return serverChannel.queuedFrames == 1
	}, time.Second, time.Millisecond)
	_, _ = clientChannel.SendRequest(context.Background(), "three", nil, false)

	require.Eventually(t, func() bool {
		return context.Cause(serverSession.Context()) != nil
	}, time.Second, time.Millisecond)
	close(blockRequests)
	require.ErrorIs(t, serverSession.Wait(), errResourceLimit)
}

func TestSessionChannelContextCancelsOnRemoteClose(t *testing.T) {
	serverChannels := make(chan *Channel, 1)
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, testHandler{
		onChannelOpen: func(_ context.Context, _ ChannelOpenRequest) ChannelOpenDecision {
			return ChannelOpenDecision{
				OK: true,
				Handler: testChannelHandler{
					onOpen: func(_ context.Context, ch *Channel) {
						serverChannels <- ch
					},
				},
			}
		},
	})
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

	clientChannel, err := clientSession.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	serverChannel := <-serverChannels

	require.NoError(t, clientChannel.Close())

	select {
	case <-serverChannel.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for channel context cancellation")
	}
}

func TestSessionCloseIsIdempotent(t *testing.T) {
	clientSession, serverSession := activatedSessionPair(t, Config{}, nil, nil)
	defer serverSession.Close() //nolint:errcheck

	require.NoError(t, clientSession.Close())
	require.NoError(t, clientSession.Close())
	require.ErrorIs(t, clientSession.Wait(), context.Canceled)
}

type testHandler struct {
	onChannelOpen   func(ctx context.Context, req ChannelOpenRequest) ChannelOpenDecision
	onGlobalRequest func(ctx context.Context, req GlobalRequest) GlobalResponse
}

func (h testHandler) OnChannelOpen(ctx context.Context, req ChannelOpenRequest) ChannelOpenDecision {
	if h.onChannelOpen != nil {
		return h.onChannelOpen(ctx, req)
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

type testChannelHandler struct {
	onOpen    func(ctx context.Context, ch *Channel)
	onRequest func(ctx context.Context, ch *Channel, req ChannelRequest) ChannelResponse
	onEOF     func(ctx context.Context, ch *Channel)
	onClose   func(ctx context.Context, ch *Channel)
}

func (h testChannelHandler) OnOpen(ctx context.Context, ch *Channel) {
	if h.onOpen != nil {
		h.onOpen(ctx, ch)
	}
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

func activatedSessionPair(t *testing.T, cfg Config, clientHandler Handler, serverHandler Handler) (*Session, *Session) {
	return activatedSessionPairWithContexts(t, context.Background(), context.Background(), cfg, clientHandler, serverHandler)
}

func activatedSessionPairWithContexts(
	t *testing.T,
	clientContext context.Context,
	serverContext context.Context,
	cfg Config,
	clientHandler Handler,
	serverHandler Handler,
) (*Session, *Session) {
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
		prepared, err := Prepare(cfg, serverHandler, Options{})
		if err != nil {
			serverErrCh <- err
			return
		}
		sess, err := prepared.Bind(serverContext, secureConn)
		if err == nil {
			sess.Activate()
			serverSessionCh <- sess
		}
		serverErrCh <- err
	}()

	secureConn, err := transport.HandshakeClient(clientConn)
	require.NoError(t, err)
	prepared, err := Prepare(cfg, clientHandler, Options{})
	require.NoError(t, err)
	clientSession, err := prepared.Bind(clientContext, secureConn)
	require.NoError(t, err)
	clientSession.Activate()
	require.NoError(t, <-serverErrCh)

	return clientSession, <-serverSessionCh
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
