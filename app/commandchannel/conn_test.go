package commandchannel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	commandprotocol "github.com/Mikadore/mygosh/lib/command"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/stretchr/testify/require"
)

func TestCompleteCommandExchangeOverSessionData(t *testing.T) {
	clientWire, serverWire := framedPair()
	var sessionRequests atomic.Int32
	serverHandler := commandSessionHandler{
		start: func(_ context.Context, request commandprotocol.StartRequest) (commandprotocol.RunningProcess, error) {
			if request.Command == "reject" {
				return nil, errors.New("rejected locally")
			}
			return &adapterProcess{
				stdout: io.NopCloser(bytes.NewReader([]byte{0x00, 0xff, 'x'})),
				stderr: io.NopCloser(bytes.NewReader([]byte("err"))),
			}, nil
		},
		requests: &sessionRequests,
	}
	clientPrepared, err := session.Prepare(session.Config{MaxPacketSize: 64}, nil, session.Options{})
	require.NoError(t, err)
	serverPrepared, err := session.Prepare(session.Config{MaxPacketSize: 64}, serverHandler, session.Options{})
	require.NoError(t, err)
	clientSession, err := clientPrepared.Bind(context.Background(), clientWire)
	require.NoError(t, err)
	serverSession, err := serverPrepared.Bind(context.Background(), serverWire)
	require.NoError(t, err)
	clientSession.Activate()
	serverSession.Activate()
	defer clientSession.Close() //nolint:errcheck
	defer serverSession.Close() //nolint:errcheck

	rejectedChannel, err := clientSession.OpenChannel(context.Background(), commandprotocol.ChannelType, nil)
	require.NoError(t, err)
	rejectedConn, err := New(rejectedChannel)
	require.NoError(t, err)
	rejectedClient, err := commandprotocol.NewClient(rejectedConn)
	require.NoError(t, err)
	err = rejectedClient.Start(context.Background(), commandprotocol.StartRequest{
		Kind:    commandprotocol.StartExec,
		Command: "reject",
	}, commandprotocol.OutputSink{Stdout: io.Discard, Stderr: io.Discard})
	var rejection *commandprotocol.StartRejectedError
	require.ErrorAs(t, err, &rejection)

	commandChannel, err := clientSession.OpenChannel(context.Background(), commandprotocol.ChannelType, nil)
	require.NoError(t, err)
	commandConn, err := New(commandChannel)
	require.NoError(t, err)
	client, err := commandprotocol.NewClient(commandConn)
	require.NoError(t, err)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	require.NoError(t, client.Start(context.Background(), commandprotocol.StartRequest{
		Kind:    commandprotocol.StartExec,
		Command: "ok",
	}, commandprotocol.OutputSink{Stdout: &stdout, Stderr: &stderr}))
	require.NoError(t, client.Wait())
	require.Equal(t, []byte{0x00, 0xff, 'x'}, stdout.Bytes())
	require.Equal(t, "err", stderr.String())
	require.Zero(t, sessionRequests.Load(), "command protocol must not use session requests")

	select {
	case <-clientSession.Done():
		t.Fatal("one command channel failure closed the client session")
	case <-serverSession.Done():
		t.Fatal("one command channel failure closed the server session")
	default:
	}
}

type commandSessionHandler struct {
	start    commandprotocol.StarterFunc
	requests *atomic.Int32
}

func (h commandSessionHandler) OnChannelOpen(_ context.Context, request session.ChannelOpenRequest) session.ChannelOpenDecision {
	if request.Type != commandprotocol.ChannelType || len(request.Payload) != 0 {
		return session.ChannelOpenDecision{Code: "unsupported", Message: "unsupported"}
	}
	return session.ChannelOpenDecision{
		OK: true,
		Handler: commandSessionChannelHandler{
			start:    h.start,
			requests: h.requests,
		},
	}
}

func (commandSessionHandler) OnGlobalRequest(_ context.Context, _ session.GlobalRequest) session.GlobalResponse {
	return session.GlobalResponse{Code: "unsupported", Message: "unsupported"}
}

type commandSessionChannelHandler struct {
	start    commandprotocol.Starter
	requests *atomic.Int32
}

func (h commandSessionChannelHandler) OnOpen(_ context.Context, channel *session.Channel) {
	conn, err := New(channel)
	if err != nil {
		_ = channel.Close()
		return
	}
	go func() {
		_ = commandprotocol.Serve(conn, h.start)
	}()
}

func (h commandSessionChannelHandler) OnRequest(_ context.Context, _ *session.Channel, _ session.ChannelRequest) session.ChannelResponse {
	h.requests.Add(1)
	return session.ChannelResponse{Code: "unsupported", Message: "unsupported"}
}

func (commandSessionChannelHandler) OnEOF(_ context.Context, _ *session.Channel)   {}
func (commandSessionChannelHandler) OnClose(_ context.Context, _ *session.Channel) {}

type adapterProcess struct {
	stdout io.ReadCloser
	stderr io.ReadCloser
}

func (p *adapterProcess) Stdout() io.Reader { return p.stdout }
func (p *adapterProcess) Stderr() io.Reader { return p.stderr }
func (*adapterProcess) WriteStdin(context.Context, []byte) error {
	return nil
}
func (*adapterProcess) CloseStdin() error                                        { return nil }
func (*adapterProcess) Resize(context.Context, commandprotocol.WindowSize) error { return nil }
func (*adapterProcess) Wait() commandprotocol.ExitResult                         { return commandprotocol.ExitResult{} }
func (*adapterProcess) Terminate(error)                                          {}
func (p *adapterProcess) CloseOutput() error {
	if p.stdout != nil {
		_ = p.stdout.Close()
	}
	if p.stderr != nil {
		_ = p.stderr.Close()
	}
	return nil
}

type memoryFramedConn struct {
	in         <-chan []byte
	out        chan<- []byte
	closed     chan struct{}
	peerClosed <-chan struct{}
	once       sync.Once
}

func framedPair() (*memoryFramedConn, *memoryFramedConn) {
	aToB := make(chan []byte, 256)
	bToA := make(chan []byte, 256)
	aClosed := make(chan struct{})
	bClosed := make(chan struct{})
	return &memoryFramedConn{
			in: bToA, out: aToB, closed: aClosed, peerClosed: bClosed,
		}, &memoryFramedConn{
			in: aToB, out: bToA, closed: bClosed, peerClosed: aClosed,
		}
}

func (c *memoryFramedConn) SendFrame(frame []byte) error {
	copy := append([]byte(nil), frame...)
	select {
	case c.out <- copy:
		return nil
	case <-c.closed:
		return io.ErrClosedPipe
	case <-c.peerClosed:
		return io.ErrClosedPipe
	}
}

func (c *memoryFramedConn) ReceiveFrame() ([]byte, error) {
	select {
	case frame := <-c.in:
		return append([]byte(nil), frame...), nil
	case <-c.closed:
		return nil, io.EOF
	case <-c.peerClosed:
		return nil, io.EOF
	}
}

func (c *memoryFramedConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}
