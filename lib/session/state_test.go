package session

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/stretchr/testify/require"
)

func TestSessionParentCancellationClosesActiveConnection(t *testing.T) {
	parent, cancel := context.WithCancelCause(context.Background())
	client, server := activatedSessionPairWithContexts(
		t,
		parent,
		context.Background(),
		Config{},
		nil,
		nil,
	)
	defer server.Close() //nolint:errcheck

	cause := errors.New("application shutdown")
	cancel(cause)
	require.ErrorIs(t, client.Wait(), cause)

	select {
	case <-server.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not observe canceled connection")
	}
}

func TestSessionCleanPeerEOFHasNilTerminalResult(t *testing.T) {
	client, server := activatedSessionPair(t, Config{}, nil, nil)
	server.closeUnderlyingConn()
	require.NoError(t, client.Wait())
}

func TestSessionRejectsDuplicatePeerChannelID(t *testing.T) {
	serverChannels := make(chan *Channel, 1)
	client, server := activatedSessionPair(t, Config{}, nil, acceptingHandler(serverChannels, nil))
	defer server.Close() //nolint:errcheck

	_, err := client.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	serverChannel := <-serverChannels

	require.NoError(t, wire.SendProto(server.conn, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelOpen{
			ChannelOpen: &sessionpb.ChannelOpen{
				ChannelType:     "session",
				SenderChannelId: serverChannel.id,
				InitialWindow:   1024,
				MaxPacketSize:   1024,
			},
		},
	}))
	require.ErrorContains(t, client.Wait(), "duplicate peer channel id")
}

func TestSessionRejectsDataAfterRemoteEOF(t *testing.T) {
	serverChannels := make(chan *Channel, 1)
	client, server := activatedSessionPair(t, Config{}, nil, acceptingHandler(serverChannels, nil))
	defer server.Close() //nolint:errcheck

	clientChannel, err := client.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	serverChannel := <-serverChannels
	require.NoError(t, serverChannel.CloseWrite())

	require.NoError(t, wire.SendProto(server.conn, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelData{
			ChannelData: &sessionpb.ChannelData{
				RecipientChannelId: clientChannel.id,
				Data:               []byte("late"),
			},
		},
	}))
	require.ErrorContains(t, client.Wait(), "remote-eof")
}

func TestCanceledGlobalWaiterIsRemovedAndLateResultIsFatal(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client, server := activatedSessionPair(t, Config{}, nil, testHandler{
		onGlobalRequest: func(_ context.Context, _ GlobalRequest) GlobalResponse {
			close(started)
			<-release
			return GlobalResponse{OK: true}
		},
	})
	defer server.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.SendGlobalRequest(ctx, "wait", nil, true)
		result <- err
	}()
	<-started
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)

	client.mu.Lock()
	require.Empty(t, client.pendingGlobal)
	client.mu.Unlock()

	close(release)
	require.ErrorContains(t, client.Wait(), "unknown request")
}

func TestCanceledOpenAndChannelRequestWaitersAreRemoved(t *testing.T) {
	t.Run("open", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		client, server := activatedSessionPair(t, Config{}, nil, testHandler{
			onChannelOpen: func(_ context.Context, _ ChannelOpenRequest) ChannelOpenDecision {
				close(started)
				<-release
				return ChannelOpenDecision{OK: true}
			},
		})
		defer server.Close() //nolint:errcheck

		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := client.OpenChannel(ctx, "session", nil)
			result <- err
		}()
		<-started
		cancel()
		require.ErrorIs(t, <-result, context.Canceled)
		client.mu.Lock()
		require.Empty(t, client.channels)
		require.Zero(t, client.pendingOpens)
		client.mu.Unlock()

		close(release)
		require.ErrorContains(t, client.Wait(), "unknown channel")
	})

	t.Run("channel request", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		channels := make(chan *Channel, 1)
		client, server := activatedSessionPair(t, Config{}, nil, acceptingHandler(channels, testChannelHandler{
			onRequest: func(_ context.Context, _ *Channel, _ ChannelRequest) ChannelResponse {
				close(started)
				<-release
				return ChannelResponse{OK: true}
			},
		}))
		defer server.Close() //nolint:errcheck

		clientChannel, err := client.OpenChannel(context.Background(), "session", nil)
		require.NoError(t, err)
		<-channels

		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := clientChannel.SendRequest(ctx, "exec", nil, true)
			result <- err
		}()
		<-started
		cancel()
		require.ErrorIs(t, <-result, context.Canceled)
		clientChannel.mu.Lock()
		require.Empty(t, clientChannel.pendingRequests)
		clientChannel.mu.Unlock()
		client.mu.Lock()
		require.Zero(t, client.pendingChannelRequests)
		client.mu.Unlock()

		close(release)
		require.ErrorContains(t, client.Wait(), "unknown request")
	})
}

func TestRequestsRemainValidAcrossEOF(t *testing.T) {
	requests := make(chan ChannelRequest, 1)
	channels := make(chan *Channel, 1)
	client, server := activatedSessionPair(t, Config{}, nil, acceptingHandler(channels, testChannelHandler{
		onRequest: func(_ context.Context, _ *Channel, request ChannelRequest) ChannelResponse {
			requests <- request
			return ChannelResponse{OK: true}
		},
	}))
	defer client.Close() //nolint:errcheck
	defer server.Close() //nolint:errcheck

	clientChannel, err := client.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	serverChannel := <-channels
	require.NoError(t, serverChannel.CloseWrite())

	response, err := clientChannel.SendRequest(context.Background(), "after-eof", nil, true)
	require.NoError(t, err)
	require.True(t, response.OK)
	require.Equal(t, "after-eof", (<-requests).Type)
}

func TestDuplicateEOFIsFatal(t *testing.T) {
	channels := make(chan *Channel, 1)
	client, server := activatedSessionPair(t, Config{}, nil, acceptingHandler(channels, nil))
	defer server.Close() //nolint:errcheck

	clientChannel, err := client.OpenChannel(context.Background(), "session", nil)
	require.NoError(t, err)
	serverChannel := <-channels
	require.NoError(t, serverChannel.CloseWrite())
	require.NoError(t, wire.SendProto(server.conn, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelEof{
			ChannelEof: &sessionpb.ChannelEof{RecipientChannelId: clientChannel.id},
		},
	}))
	require.ErrorContains(t, client.Wait(), "duplicate channel EOF")
}

func TestSessionEnforcesChannelAndControlLimits(t *testing.T) {
	t.Run("channels", func(t *testing.T) {
		channels := make(chan *Channel, 2)
		cfg := Config{Limits: Limits{MaxChannels: 1, MaxPendingOpens: 1}}
		client, server := activatedSessionPair(t, cfg, nil, acceptingHandler(channels, nil))
		defer client.Close() //nolint:errcheck
		defer server.Close() //nolint:errcheck

		_, err := client.OpenChannel(context.Background(), "session", nil)
		require.NoError(t, err)
		<-channels
		_, err = client.OpenChannel(context.Background(), "session", nil)
		require.ErrorIs(t, err, errResourceLimit)
	})

	t.Run("control payload", func(t *testing.T) {
		cfg := Config{Limits: Limits{MaxControlPayload: 4}}
		client, server := activatedSessionPair(t, cfg, nil, nil)
		defer client.Close() //nolint:errcheck
		defer server.Close() //nolint:errcheck

		_, err := client.OpenChannel(context.Background(), "session", []byte("12345"))
		require.ErrorContains(t, err, "control payload exceeds limit")
	})

	t.Run("queued bytes", func(t *testing.T) {
		channels := make(chan *Channel, 1)
		cfg := Config{
			InitialWindow:         8,
			MaxPacketSize:         4,
			WindowAdjustThreshold: 1,
			Limits: Limits{
				MaxQueuedBytesPerChannel: 4,
			},
		}
		client, server := activatedSessionPair(t, cfg, nil, acceptingHandler(channels, nil))
		defer client.Close() //nolint:errcheck

		clientChannel, err := client.OpenChannel(context.Background(), "session", nil)
		require.NoError(t, err)
		<-channels
		require.NoError(t, clientChannel.Send(context.Background(), []byte("1234")))
		_ = clientChannel.Send(context.Background(), []byte("5"))
		require.ErrorIs(t, server.Wait(), errResourceLimit)
	})
}

func TestPendingRequestLimitsRecoverAfterCompletion(t *testing.T) {
	t.Run("channel", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		var first sync.Once
		channels := make(chan *Channel, 1)
		cfg := Config{Limits: Limits{
			MaxPendingChannelRequests:           1,
			MaxPendingChannelRequestsPerChannel: 1,
		}}
		client, server := activatedSessionPair(t, cfg, nil, acceptingHandler(channels, testChannelHandler{
			onRequest: func(_ context.Context, _ *Channel, _ ChannelRequest) ChannelResponse {
				first.Do(func() {
					close(started)
					<-release
				})
				return ChannelResponse{OK: true}
			},
		}))
		defer client.Close() //nolint:errcheck
		defer server.Close() //nolint:errcheck

		channel, err := client.OpenChannel(context.Background(), "session", nil)
		require.NoError(t, err)
		<-channels

		firstResult := make(chan error, 1)
		go func() {
			_, err := channel.SendRequest(context.Background(), "one", nil, true)
			firstResult <- err
		}()
		<-started
		_, err = channel.SendRequest(context.Background(), "two", nil, true)
		require.ErrorContains(t, err, "pending request limit")

		close(release)
		require.NoError(t, <-firstResult)
		response, err := channel.SendRequest(context.Background(), "three", nil, true)
		require.NoError(t, err)
		require.True(t, response.OK)
	})

	t.Run("global", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		var first sync.Once
		cfg := Config{Limits: Limits{MaxPendingGlobalRequests: 1}}
		client, server := activatedSessionPair(t, cfg, nil, testHandler{
			onGlobalRequest: func(_ context.Context, _ GlobalRequest) GlobalResponse {
				first.Do(func() {
					close(started)
					<-release
				})
				return GlobalResponse{OK: true}
			},
		})
		defer client.Close() //nolint:errcheck
		defer server.Close() //nolint:errcheck

		firstResult := make(chan error, 1)
		go func() {
			_, err := client.SendGlobalRequest(context.Background(), "one", nil, true)
			firstResult <- err
		}()
		<-started
		_, err := client.SendGlobalRequest(context.Background(), "two", nil, true)
		require.ErrorContains(t, err, "pending global request limit")

		close(release)
		require.NoError(t, <-firstResult)
		response, err := client.SendGlobalRequest(context.Background(), "three", nil, true)
		require.NoError(t, err)
		require.True(t, response.OK)
	})
}

func TestSessionRejectsEmptyDataAndIDExhaustion(t *testing.T) {
	client, server := activatedSessionPair(t, Config{}, nil, nil)
	defer client.Close() //nolint:errcheck
	defer server.Close() //nolint:errcheck

	client.mu.Lock()
	client.nextLocalChannelID = math.MaxUint64
	client.mu.Unlock()
	_, err := client.OpenChannel(context.Background(), "session", nil)
	require.ErrorContains(t, err, "id space exhausted")

	ch := newPendingChannel(client, 7, "session", nil)
	ch.state = channelOpen
	require.ErrorContains(t, ch.Send(context.Background(), nil), "empty channel data")
}

func TestLocalChannelCloseIsRemovedAfterTimeout(t *testing.T) {
	framer := newBlockingFramedConn()
	prepared, err := Prepare(Config{ChannelCloseTimeout: 20 * time.Millisecond}, nil, Options{})
	require.NoError(t, err)
	sess, err := prepared.Bind(context.Background(), framer)
	require.NoError(t, err)
	sess.Activate()
	defer sess.Close() //nolint:errcheck

	ch := newIncomingChannel(sess, 0, 7, "session", 1024, 1024, nil)
	ch.state = channelOpen
	ch.slot = channelSlotActive
	sess.mu.Lock()
	sess.channels[ch.id] = ch
	sess.peerChannelIDs[ch.peerID] = ch.id
	sess.activeChannels = 1
	sess.mu.Unlock()

	require.NoError(t, ch.Close())
	require.Eventually(t, func() bool {
		return sess.lookupChannel(ch.id) == nil
	}, time.Second, 5*time.Millisecond)
}

func TestQueuedWriteCancellationReleasesBudget(t *testing.T) {
	framer := newControlledWriteFramedConn()
	prepared, err := Prepare(Config{}, nil, Options{})
	require.NoError(t, err)
	sess, err := prepared.Bind(context.Background(), framer)
	require.NoError(t, err)
	sess.Activate()
	defer sess.Close() //nolint:errcheck

	firstResult := make(chan error, 1)
	go func() {
		_, err := sess.SendGlobalRequest(context.Background(), "first", nil, false)
		firstResult <- err
	}()
	<-framer.writeStarted

	ctx, cancel := context.WithCancel(context.Background())
	secondResult := make(chan error, 1)
	go func() {
		_, err := sess.SendGlobalRequest(ctx, "second", nil, false)
		secondResult <- err
	}()
	require.Eventually(t, func() bool {
		sess.budgetMu.Lock()
		defer sess.budgetMu.Unlock()
		return sess.queuedFrames == 1
	}, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-secondResult, context.Canceled)

	close(framer.allowWrite)
	require.NoError(t, <-firstResult)
	require.Eventually(t, func() bool {
		sess.budgetMu.Lock()
		defer sess.budgetMu.Unlock()
		return sess.queuedFrames == 0 && sess.queuedBytes == 0
	}, time.Second, time.Millisecond)
}

func TestStartedWriteFailureIsConnectionFatal(t *testing.T) {
	framer := &failingFramedConn{blockingFramedConn: newBlockingFramedConn()}
	prepared, err := Prepare(Config{}, nil, Options{})
	require.NoError(t, err)
	sess, err := prepared.Bind(context.Background(), framer)
	require.NoError(t, err)
	sess.Activate()

	_, err = sess.SendGlobalRequest(context.Background(), "fail", nil, false)
	require.ErrorContains(t, err, "send session envelope")
	require.ErrorContains(t, sess.Wait(), "send session envelope")
}

func acceptingHandler(channels chan<- *Channel, handler ChannelHandler) Handler {
	return testHandler{
		onChannelOpen: func(_ context.Context, _ ChannelOpenRequest) ChannelOpenDecision {
			if handler == nil {
				handler = testChannelHandler{}
			}
			return ChannelOpenDecision{
				OK: true,
				Handler: openCaptureHandler{
					ChannelHandler: handler,
					opened:         channels,
				},
			}
		},
	}
}

type openCaptureHandler struct {
	ChannelHandler
	opened chan<- *Channel
}

func (h openCaptureHandler) OnOpen(ctx context.Context, ch *Channel) {
	h.ChannelHandler.OnOpen(ctx, ch)
	h.opened <- ch
}

type blockingFramedConn struct {
	closeOnce sync.Once
	closed    chan struct{}
}

type controlledWriteFramedConn struct {
	*blockingFramedConn
	writeStarted chan struct{}
	allowWrite   chan struct{}
	startOnce    sync.Once
}

func newControlledWriteFramedConn() *controlledWriteFramedConn {
	return &controlledWriteFramedConn{
		blockingFramedConn: newBlockingFramedConn(),
		writeStarted:       make(chan struct{}),
		allowWrite:         make(chan struct{}),
	}
}

func (f *controlledWriteFramedConn) SendFrame([]byte) error {
	f.startOnce.Do(func() {
		close(f.writeStarted)
		<-f.allowWrite
	})
	return nil
}

type failingFramedConn struct {
	*blockingFramedConn
}

func (*failingFramedConn) SendFrame([]byte) error {
	return errors.New("write failed")
}

func newBlockingFramedConn() *blockingFramedConn {
	return &blockingFramedConn{closed: make(chan struct{})}
}

func (*blockingFramedConn) SendFrame([]byte) error {
	return nil
}

func (f *blockingFramedConn) ReceiveFrame() ([]byte, error) {
	<-f.closed
	return nil, io.EOF
}

func (f *blockingFramedConn) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)
	})
	return nil
}
