package command

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/Mikadore/mygosh/lib/command/commandpb"
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

type Client struct {
	conn FrameConn

	mu       sync.Mutex
	writeMu  sync.Mutex
	state    clientState
	hasPTY   bool
	stdinEOF bool
	sink     OutputSink
	started  chan error
	done     chan struct{}
	waitErr  error
	close    sync.Once
}

func NewClient(conn FrameConn) (*Client, error) {
	if err := validateFrameConn(conn); err != nil {
		return nil, err
	}
	return &Client{
		conn:    conn,
		state:   clientIdle,
		started: make(chan error, 1),
		done:    make(chan struct{}),
	}, nil
}

func (c *Client) Start(ctx context.Context, request StartRequest, sink OutputSink) error {
	ctx = normalizeContext(ctx)
	frame, err := encodeStart(request)
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
	if err := c.sendMessage(ctx, frame); err != nil {
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

func (c *Client) WriteStdin(ctx context.Context, data []byte) error {
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

	frames, err := chunkedFrames(data, c.conn.MaxSendFrameSize(), func(chunk []byte) *commandpb.ClientFrame {
		return &commandpb.ClientFrame{
			Kind: &commandpb.ClientFrame_Stdin{
				Stdin: &commandpb.Stdin{Data: append([]byte(nil), chunk...)},
			},
		}
	})
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

func (c *Client) CloseStdin(ctx context.Context) error {
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

	return c.sendMessage(ctx, &commandpb.ClientFrame{
		Kind: &commandpb.ClientFrame_StdinEof{StdinEof: &commandpb.StdinEof{}},
	})
}

func (c *Client) Resize(ctx context.Context, size WindowSize) error {
	ctx = normalizeContext(ctx)
	c.mu.Lock()
	if c.state != clientRunning || !c.hasPTY {
		c.mu.Unlock()
		return protocolErrorf("window change requires an accepted PTY start")
	}
	c.mu.Unlock()

	return c.sendMessage(ctx, &commandpb.ClientFrame{
		Kind: &commandpb.ClientFrame_WindowChange{
			WindowChange: &commandpb.WindowChange{Rows: size.Rows, Columns: size.Columns},
		},
	})
}

func (c *Client) Wait() error {
	if c == nil {
		return eris.New("command client is required")
	}
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.waitErr
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.finish(context.Canceled)
	return nil
}

func (c *Client) receiveLoop() {
	for {
		frame, err := c.conn.ReceiveFrame(c.conn.Context())
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			c.finish(eris.Wrap(err, "receive command frame"))
			return
		}
		var message commandpb.ServerFrame
		if err := unmarshalMessage(frame, &message); err != nil {
			c.finish(protocolErrorf("invalid server frame: %v", err))
			return
		}
		if err := c.handleServerFrame(&message); err != nil {
			c.finish(err)
			return
		}
	}
}

func (c *Client) handleServerFrame(frame *commandpb.ServerFrame) error {
	c.mu.Lock()
	state := c.state
	sink := c.sink
	c.mu.Unlock()

	switch kind := frame.GetKind().(type) {
	case *commandpb.ServerFrame_StartResult:
		if state != clientStarting {
			return protocolErrorf("duplicate or out-of-order start result")
		}
		result := kind.StartResult
		if result.GetAccepted() {
			if result.GetCode() != "" || result.GetMessage() != "" {
				return protocolErrorf("accepted start result contains rejection details")
			}
			c.mu.Lock()
			c.state = clientRunning
			c.mu.Unlock()
			c.started <- nil
			return nil
		}
		err := &StartRejectedError{Code: result.GetCode(), Message: result.GetMessage()}
		c.started <- err
		return err
	case *commandpb.ServerFrame_Stdout:
		if state != clientRunning {
			return protocolErrorf("stdout before start acceptance or after exit")
		}
		if sink.Stdout == nil {
			return protocolErrorf("stdout sink is not configured")
		}
		if _, err := sink.Stdout.Write(kind.Stdout.GetData()); err != nil {
			return eris.Wrap(err, "write command stdout")
		}
		return nil
	case *commandpb.ServerFrame_Stderr:
		if state != clientRunning {
			return protocolErrorf("stderr before start acceptance or after exit")
		}
		if c.hasPTY {
			return protocolErrorf("stderr is not legal for a PTY command")
		}
		if sink.Stderr == nil {
			return protocolErrorf("stderr sink is not configured")
		}
		if _, err := sink.Stderr.Write(kind.Stderr.GetData()); err != nil {
			return eris.Wrap(err, "write command stderr")
		}
		return nil
	case *commandpb.ServerFrame_Exit:
		if state != clientRunning {
			return protocolErrorf("duplicate or out-of-order exit")
		}
		var waitErr error
		switch result := kind.Exit.GetResult().(type) {
		case *commandpb.Exit_Status:
			if result.Status != 0 {
				waitErr = &ExitStatusError{Status: int(result.Status)}
			}
		case *commandpb.Exit_Signal:
			waitErr = &ExitSignalError{Signal: result.Signal}
		case *commandpb.Exit_RuntimeFailure:
			waitErr = &RuntimeError{Message: result.RuntimeFailure.GetMessage()}
		default:
			return protocolErrorf("exit result is required")
		}
		c.mu.Lock()
		c.state = clientExited
		c.waitErr = waitErr
		c.mu.Unlock()
		c.finish(waitErr)
		return nil
	default:
		return protocolErrorf("unsupported server frame %T", frame.GetKind())
	}
}

func (c *Client) sendMessage(ctx context.Context, message *commandpb.ClientFrame) error {
	frame, err := marshalMessage(message, c.conn.MaxSendFrameSize())
	if err != nil {
		return err
	}
	return c.sendEncoded(ctx, frame)
}

func (c *Client) sendEncoded(ctx context.Context, frame []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.SendFrame(ctx, frame)
}

func (c *Client) finish(err error) {
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
