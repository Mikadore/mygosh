package command

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Mikadore/mygosh/lib/command/commandpb"
	"github.com/stretchr/testify/require"
)

func TestMalformedInitialFrameReceivesRejection(t *testing.T) {
	clientConn, serverConn := frameConnPair(128)
	var starterCalled atomic.Bool
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- Serve(serverConn, StarterFunc(func(context.Context, StartRequest) (RunningProcess, error) {
			starterCalled.Store(true)
			return newFakeProcess(ExitResult{}), nil
		}))
	}()

	require.NoError(t, sendClientMessage(clientConn, &commandpb.ClientFrame{
		Kind: &commandpb.ClientFrame_Stdin{Stdin: &commandpb.Stdin{Data: []byte("bad")}},
	}))
	frame, err := clientConn.ReceiveFrame(context.Background())
	require.NoError(t, err)
	var response commandpb.ServerFrame
	require.NoError(t, unmarshalMessage(frame, &response))
	require.False(t, response.GetStartResult().GetAccepted())
	require.ErrorContains(t, <-serverErr, "first client frame must be start")
	require.False(t, starterCalled.Load())
}

func TestPostStartProtocolFailureTerminatesAndSendsRuntimeExit(t *testing.T) {
	clientConn, serverConn := frameConnPair(128)
	process := newWaitingFakeProcess()
	process.finishOnEOF = false
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- Serve(serverConn, StarterFunc(func(context.Context, StartRequest) (RunningProcess, error) {
			return process, nil
		}))
	}()

	require.NoError(t, sendClientMessage(clientConn, &commandpb.ClientFrame{
		Kind: &commandpb.ClientFrame_Start{Start: &commandpb.Start{
			ProtocolVersion: ProtocolVersion,
			Target:          &commandpb.Start_Exec{Exec: &commandpb.Exec{Command: "true"}},
		}},
	}))
	_, err := clientConn.ReceiveFrame(context.Background())
	require.NoError(t, err)
	eof := &commandpb.ClientFrame{Kind: &commandpb.ClientFrame_StdinEof{StdinEof: &commandpb.StdinEof{}}}
	require.NoError(t, sendClientMessage(clientConn, eof))
	require.NoError(t, sendClientMessage(clientConn, eof))

	frame, err := clientConn.ReceiveFrame(context.Background())
	require.NoError(t, err)
	var response commandpb.ServerFrame
	require.NoError(t, unmarshalMessage(frame, &response))
	require.NotNil(t, response.GetExit().GetRuntimeFailure())
	require.ErrorContains(t, <-serverErr, "duplicate stdin EOF")
	process.mu.Lock()
	require.True(t, process.terminated)
	process.mu.Unlock()
}

func sendClientMessage(conn FrameConn, message *commandpb.ClientFrame) error {
	frame, err := marshalMessage(message, conn.MaxSendFrameSize())
	if err != nil {
		return err
	}
	return conn.SendFrame(context.Background(), frame)
}

func sendServerMessage(conn FrameConn, message *commandpb.ServerFrame) error {
	frame, err := marshalMessage(message, conn.MaxSendFrameSize())
	if err != nil {
		return err
	}
	return conn.SendFrame(context.Background(), frame)
}

type memoryFrameConn struct {
	ctx        context.Context
	cancel     context.CancelFunc
	in         <-chan []byte
	out        chan<- []byte
	peerClosed <-chan struct{}
	closed     chan struct{}
	closeOnce  sync.Once
	maximum    int
}

func frameConnPair(maximum int) (*memoryFrameConn, *memoryFrameConn) {
	aToB := make(chan []byte)
	bToA := make(chan []byte)
	aClosed := make(chan struct{})
	bClosed := make(chan struct{})
	aCtx, aCancel := context.WithCancel(context.Background())
	bCtx, bCancel := context.WithCancel(context.Background())
	return &memoryFrameConn{
			ctx: aCtx, cancel: aCancel, in: bToA, out: aToB,
			peerClosed: bClosed, closed: aClosed, maximum: maximum,
		}, &memoryFrameConn{
			ctx: bCtx, cancel: bCancel, in: aToB, out: bToA,
			peerClosed: aClosed, closed: bClosed, maximum: maximum,
		}
}

func (c *memoryFrameConn) Context() context.Context {
	return c.ctx
}

func (c *memoryFrameConn) SendFrame(ctx context.Context, frame []byte) error {
	copy := append([]byte(nil), frame...)
	select {
	case c.out <- copy:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return io.ErrClosedPipe
	case <-c.peerClosed:
		return io.ErrClosedPipe
	}
}

func (c *memoryFrameConn) ReceiveFrame(ctx context.Context) ([]byte, error) {
	select {
	case frame := <-c.in:
		return append([]byte(nil), frame...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.EOF
	case <-c.peerClosed:
		return nil, io.EOF
	}
}

func (c *memoryFrameConn) MaxSendFrameSize() int {
	return c.maximum
}

func (c *memoryFrameConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		close(c.closed)
	})
	return nil
}

type fakeProcess struct {
	mu          sync.Mutex
	stdin       bytes.Buffer
	stdout      io.ReadCloser
	stderr      io.ReadCloser
	resizes     []WindowSize
	eofCount    int
	result      ExitResult
	wait        chan struct{}
	waitOnce    sync.Once
	eofReceived chan struct{}
	eofOnce     sync.Once
	terminated  bool
	finishOnEOF bool
}

func newFakeProcess(result ExitResult) *fakeProcess {
	wait := make(chan struct{})
	close(wait)
	return &fakeProcess{
		stdout:      io.NopCloser(bytes.NewReader(nil)),
		stderr:      io.NopCloser(bytes.NewReader(nil)),
		result:      result,
		wait:        wait,
		eofReceived: make(chan struct{}),
		finishOnEOF: true,
	}
}

func newWaitingFakeProcess() *fakeProcess {
	return &fakeProcess{
		stdout:      io.NopCloser(bytes.NewReader(nil)),
		wait:        make(chan struct{}),
		eofReceived: make(chan struct{}),
		finishOnEOF: true,
	}
}

func (p *fakeProcess) Stdout() io.Reader { return p.stdout }
func (p *fakeProcess) Stderr() io.Reader { return p.stderr }

func (p *fakeProcess) WriteStdin(_ context.Context, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.stdin.Write(data)
	return err
}

func (p *fakeProcess) CloseStdin() error {
	p.mu.Lock()
	p.eofCount++
	finish := p.finishOnEOF
	p.mu.Unlock()
	p.eofOnce.Do(func() {
		close(p.eofReceived)
	})
	if finish {
		p.finish()
	}
	return nil
}

func (p *fakeProcess) Resize(_ context.Context, size WindowSize) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resizes = append(p.resizes, size)
	return nil
}

func (p *fakeProcess) Wait() ExitResult {
	<-p.wait
	return p.result
}

func (p *fakeProcess) Terminate(error) {
	p.mu.Lock()
	p.terminated = true
	p.mu.Unlock()
	p.finish()
}

func (p *fakeProcess) CloseOutput() error {
	if p.stdout != nil {
		_ = p.stdout.Close()
	}
	if p.stderr != nil {
		_ = p.stderr.Close()
	}
	return nil
}

func (p *fakeProcess) finish() {
	p.waitOnce.Do(func() {
		close(p.wait)
	})
}
