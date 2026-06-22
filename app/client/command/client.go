package command

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"

	commandprotocol "github.com/Mikadore/mygosh/lib/command"
	"github.com/rotisserie/eris"
)

type clientState uint8

const (
	clientIdle clientState = iota
	clientStarting
	clientRunning
	clientExited
	clientClosed
)

type outputSink struct {
	stdout io.Writer
	stderr io.Writer
}

type client struct {
	conn commandprotocol.FrameConn

	mu       sync.Mutex
	writeMu  sync.Mutex
	state    clientState
	hasPTY   bool
	stdinEOF bool
	sink     outputSink
	started  chan error
	done     chan struct{}
	waitErr  error
	close    sync.Once
}

func newClient(conn commandprotocol.FrameConn) (*client, error) {
	if conn == nil {
		return nil, eris.New("command frame connection is required")
	}
	if conn.MaxSendFrameSize() <= 0 {
		return nil, eris.New("command maximum send frame size must be greater than zero")
	}
	return &client{
		conn:    conn,
		state:   clientIdle,
		started: make(chan error, 1),
		done:    make(chan struct{}),
	}, nil
}

func (c *client) start(ctx context.Context, request commandprotocol.StartRequest, sink outputSink) error {
	ctx = normalizeContext(ctx)
	frame, err := commandprotocol.EncodeClientStart(request, c.conn.MaxSendFrameSize())
	if err != nil {
		return err
	}

	c.mu.Lock()
	if c.state != clientIdle {
		c.mu.Unlock()
		return protocolErrorf("start may be sent exactly once")
	}
	c.state = clientStarting
	c.hasPTY = request.PTY != nil
	c.sink = sink
	c.mu.Unlock()

	go c.receiveLoop()
	if err := c.sendEncoded(ctx, frame); err != nil {
		c.finish(eris.Wrap(err, "send command start"))
		return err
	}

	select {
	case err := <-c.started:
		return err
	case <-ctx.Done():
		c.finish(ctx.Err())
		return ctx.Err()
	}
}

func (c *client) writeStdin(ctx context.Context, data []byte) error {
	ctx = normalizeContext(ctx)
	if len(data) == 0 {
		return nil
	}
	c.mu.Lock()
	if c.state != clientRunning {
		c.mu.Unlock()
		return protocolErrorf("stdin is legal only after start acceptance")
	}
	if c.stdinEOF {
		c.mu.Unlock()
		return protocolErrorf("stdin after EOF")
	}
	c.mu.Unlock()

	frames, err := commandprotocol.EncodeClientStdin(data, c.conn.MaxSendFrameSize())
	if err != nil {
		return err
	}
	for _, frame := range frames {
		if err := c.sendEncoded(ctx, frame); err != nil {
			c.finish(eris.Wrap(err, "send command stdin"))
			return err
		}
	}
	return nil
}

func (c *client) closeStdin(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	c.mu.Lock()
	if c.state != clientRunning {
		c.mu.Unlock()
		return protocolErrorf("stdin EOF is legal only after start acceptance")
	}
	if c.stdinEOF {
		c.mu.Unlock()
		return protocolErrorf("duplicate stdin EOF")
	}
	c.stdinEOF = true
	c.mu.Unlock()

	frame, err := commandprotocol.EncodeClientStdinEOF(c.conn.MaxSendFrameSize())
	if err != nil {
		return err
	}
	if err := c.sendEncoded(ctx, frame); err != nil {
		return err
	}
	slog.Default().With("component", "client-command").Debug("sent command stdin EOF")
	return nil
}

func (c *client) resize(ctx context.Context, size commandprotocol.WindowSize) error {
	ctx = normalizeContext(ctx)
	c.mu.Lock()
	if c.state != clientRunning || !c.hasPTY {
		c.mu.Unlock()
		return protocolErrorf("window change requires an accepted PTY start")
	}
	c.mu.Unlock()

	frame, err := commandprotocol.EncodeClientWindowChange(size, c.conn.MaxSendFrameSize())
	if err != nil {
		return err
	}
	return c.sendEncoded(ctx, frame)
}

func (c *client) wait() error {
	if c == nil {
		return eris.New("command client is required")
	}
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.waitErr
}

func (c *client) closeClient() error {
	if c == nil {
		return nil
	}
	c.finish(context.Canceled)
	return nil
}

func (c *client) receiveLoop() {
	for {
		frame, err := c.conn.ReceiveFrame(c.conn.Context())
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			c.finish(eris.Wrap(err, "receive command frame"))
			return
		}
		event, err := commandprotocol.DecodeServerEvent(frame)
		if err != nil {
			c.finish(protocolErrorf("invalid server frame: %v", err))
			return
		}
		if err := c.handleServerEvent(event); err != nil {
			c.finish(err)
			return
		}
	}
}

func (c *client) handleServerEvent(event commandprotocol.ServerEvent) error {
	c.mu.Lock()
	state := c.state
	sink := c.sink
	hasPTY := c.hasPTY
	c.mu.Unlock()

	switch event.Kind {
	case commandprotocol.ServerEventStartResult:
		if state != clientStarting {
			return protocolErrorf("duplicate or out-of-order start result")
		}
		if event.Accepted {
			c.mu.Lock()
			c.state = clientRunning
			c.mu.Unlock()
			c.started <- nil
			return nil
		}
		slog.Default().With("component", "client-command").Debug(
			"command start rejected",
			"code", event.Code,
		)
		err := &StartRejectedError{Code: event.Code, Message: event.Message}
		c.started <- err
		return err
	case commandprotocol.ServerEventStdout:
		if state != clientRunning {
			return protocolErrorf("stdout before start acceptance or after exit")
		}
		if sink.stdout == nil {
			return protocolErrorf("stdout sink is not configured")
		}
		if _, err := sink.stdout.Write(event.Data); err != nil {
			return eris.Wrap(err, "write command stdout")
		}
		return nil
	case commandprotocol.ServerEventStderr:
		if state != clientRunning {
			return protocolErrorf("stderr before start acceptance or after exit")
		}
		if hasPTY {
			return protocolErrorf("stderr is not legal for a PTY command")
		}
		if sink.stderr == nil {
			return protocolErrorf("stderr sink is not configured")
		}
		if _, err := sink.stderr.Write(event.Data); err != nil {
			return eris.Wrap(err, "write command stderr")
		}
		return nil
	case commandprotocol.ServerEventExit:
		if state != clientRunning {
			return protocolErrorf("duplicate or out-of-order exit")
		}
		waitErr := terminalResult(event.Exit)
		c.mu.Lock()
		c.state = clientExited
		c.waitErr = waitErr
		c.mu.Unlock()
		c.finish(waitErr)
		return nil
	default:
		return protocolErrorf("unsupported server event %d", event.Kind)
	}
}

func (c *client) sendEncoded(ctx context.Context, frame []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.SendFrame(ctx, frame)
}

func (c *client) finish(err error) {
	c.close.Do(func() {
		c.mu.Lock()
		if c.waitErr == nil {
			c.waitErr = err
		}
		if c.state == clientStarting {
			select {
			case c.started <- err:
			default:
			}
		}
		if c.state != clientExited {
			c.state = clientClosed
		}
		c.mu.Unlock()
		_ = c.conn.Close()
		close(c.done)
	})
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func protocolErrorf(format string, args ...any) error {
	return &commandprotocol.ProtocolError{Message: eris.Errorf(format, args...).Error()}
}
