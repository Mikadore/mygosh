package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/command/commandpb"
	"github.com/stretchr/testify/require"
)

func TestClientServerExecPreservesChunkedOutputAndExit(t *testing.T) {
	clientConn, serverConn := frameConnPair(48)
	terminalBytes := []byte{0x00, 0x1b, '[', '3', '1', 'm', 0xff, '\r', '\n'}
	process := newFakeProcess(ExitResult{})
	process.stdout = io.NopCloser(bytes.NewReader(bytes.Repeat(terminalBytes, 64)))
	process.stderr = io.NopCloser(bytes.NewReader([]byte("stderr")))
	starter := StarterFunc(func(_ context.Context, request StartRequest) (RunningProcess, error) {
		require.Equal(t, StartExec, request.Kind)
		require.Equal(t, "printf hello", request.Command)
		require.Equal(t, map[string]string{"LANG": "C.UTF-8"}, request.Environment)
		return process, nil
	})

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- Serve(serverConn, starter)
	}()

	client, err := NewClient(clientConn)
	require.NoError(t, err)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	require.NoError(t, client.Start(context.Background(), StartRequest{
		Kind:        StartExec,
		Command:     "printf hello",
		Environment: map[string]string{"LANG": "C.UTF-8"},
	}, OutputSink{Stdout: &stdout, Stderr: &stderr}))
	require.NoError(t, client.Wait())
	require.NoError(t, <-serverErr)
	require.Equal(t, bytes.Repeat(terminalBytes, 64), stdout.Bytes())
	require.Equal(t, "stderr", stderr.String())
}

func TestClientServerStdinEOFAndPTYResize(t *testing.T) {
	clientConn, serverConn := frameConnPair(128)
	process := newWaitingFakeProcess()
	process.finishOnEOF = false
	starter := StarterFunc(func(_ context.Context, request StartRequest) (RunningProcess, error) {
		require.Equal(t, StartShell, request.Kind)
		require.NotNil(t, request.PTY)
		return process, nil
	})
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- Serve(serverConn, starter)
	}()

	client, err := NewClient(clientConn)
	require.NoError(t, err)
	require.NoError(t, client.Start(context.Background(), StartRequest{
		Kind: StartShell,
		PTY:  &PTYRequest{Terminal: "xterm", Rows: 24, Columns: 80},
	}, OutputSink{Stdout: io.Discard, Stderr: io.Discard}))
	require.NoError(t, client.WriteStdin(context.Background(), []byte{0x00, 0xff, 'x'}))
	require.NoError(t, client.Resize(context.Background(), WindowSize{Rows: 40, Columns: 120}))
	require.NoError(t, client.CloseStdin(context.Background()))
	<-process.eofReceived
	require.ErrorContains(t, client.WriteStdin(context.Background(), []byte("late")), "stdin after EOF")
	process.finish()
	require.NoError(t, client.Wait())
	require.NoError(t, <-serverErr)

	process.mu.Lock()
	defer process.mu.Unlock()
	require.Equal(t, []byte{0x00, 0xff, 'x'}, process.stdin.Bytes())
	require.Equal(t, []WindowSize{{Rows: 40, Columns: 120}}, process.resizes)
	require.Equal(t, 1, process.eofCount)
}

func TestClientReportsTypedTerminalResults(t *testing.T) {
	tests := []struct {
		name   string
		result ExitResult
		check  func(*testing.T, error)
	}{
		{name: "status", result: ExitResult{Status: 23}, check: func(t *testing.T, err error) {
			var target *ExitStatusError
			require.ErrorAs(t, err, &target)
		}},
		{name: "signal", result: ExitResult{Signal: "SIGTERM"}, check: func(t *testing.T, err error) {
			var target *ExitSignalError
			require.ErrorAs(t, err, &target)
		}},
		{name: "runtime", result: ExitResult{RuntimeFailure: "failed"}, check: func(t *testing.T, err error) {
			var target *RuntimeError
			require.ErrorAs(t, err, &target)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := frameConnPair(128)
			go func() {
				_ = Serve(serverConn, StarterFunc(func(context.Context, StartRequest) (RunningProcess, error) {
					return newFakeProcess(test.result), nil
				}))
			}()
			client, err := NewClient(clientConn)
			require.NoError(t, err)
			require.NoError(t, client.Start(context.Background(), StartRequest{
				Kind:    StartExec,
				Command: "false",
			}, OutputSink{Stdout: io.Discard, Stderr: io.Discard}))
			err = client.Wait()
			require.Error(t, err)
			test.check(t, err)
		})
	}
}

func TestStartRejectionIsGenericAndTyped(t *testing.T) {
	clientConn, serverConn := frameConnPair(128)
	go func() {
		_ = Serve(serverConn, StarterFunc(func(context.Context, StartRequest) (RunningProcess, error) {
			return nil, errors.New("sensitive local detail")
		}))
	}()
	client, err := NewClient(clientConn)
	require.NoError(t, err)
	err = client.Start(context.Background(), StartRequest{
		Kind:    StartExec,
		Command: "true",
	}, OutputSink{Stdout: io.Discard, Stderr: io.Discard})
	var rejection *StartRejectedError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, genericStartRejectCode, rejection.Code)
	require.NotContains(t, rejection.Message, "sensitive")
}

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

func TestClientRejectsOutputBeforeStartAcceptance(t *testing.T) {
	clientConn, serverConn := frameConnPair(128)
	go func() {
		_, _ = serverConn.ReceiveFrame(context.Background())
		_ = sendServerMessage(serverConn, &commandpb.ServerFrame{
			Kind: &commandpb.ServerFrame_Stdout{Stdout: &commandpb.Stdout{Data: []byte("early")}},
		})
	}()
	client, err := NewClient(clientConn)
	require.NoError(t, err)
	err = client.Start(context.Background(), StartRequest{
		Kind:    StartExec,
		Command: "true",
	}, OutputSink{Stdout: io.Discard, Stderr: io.Discard})
	var protocolErr *ProtocolError
	require.ErrorAs(t, err, &protocolErr)
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

func TestBlockedStartSendHonorsCancellation(t *testing.T) {
	clientConn, peer := frameConnPair(128)
	defer peer.Close() //nolint:errcheck
	client, err := NewClient(clientConn)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = client.Start(ctx, StartRequest{Kind: StartExec, Command: "true"}, OutputSink{
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
