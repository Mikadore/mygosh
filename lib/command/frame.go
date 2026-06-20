package command

import (
	"context"

	"github.com/rotisserie/eris"
)

const (
	ProtocolVersion uint32 = 1
	ChannelType            = "command"

	defaultMaximumFrameSize = 16 << 10
)

// FrameConn is the transport-neutral command protocol boundary. Each call
// sends or receives exactly one command frame.
type FrameConn interface {
	Context() context.Context
	SendFrame(ctx context.Context, frame []byte) error
	ReceiveFrame(ctx context.Context) ([]byte, error)
	MaxSendFrameSize() int
	Close() error
}

func validateFrameConn(conn FrameConn) error {
	if conn == nil {
		return eris.New("command frame connection is required")
	}
	if conn.MaxSendFrameSize() <= 0 {
		return eris.New("command maximum send frame size must be greater than zero")
	}
	return nil
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
