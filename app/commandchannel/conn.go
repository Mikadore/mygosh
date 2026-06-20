package commandchannel

import (
	"context"

	"github.com/Mikadore/mygosh/lib/session"
	"github.com/rotisserie/eris"
)

// Conn adapts session channel data to the transport-neutral command framing
// contract. This is intentionally the only adapter that knows both protocols.
type Conn struct {
	channel *session.Channel
}

func New(channel *session.Channel) (*Conn, error) {
	if channel == nil {
		return nil, eris.New("session channel is required")
	}
	return &Conn{channel: channel}, nil
}

func (c *Conn) Context() context.Context {
	if c == nil || c.channel == nil {
		return context.Background()
	}
	return c.channel.Context()
}

func (c *Conn) SendFrame(ctx context.Context, frame []byte) error {
	if c == nil || c.channel == nil {
		return eris.New("command channel connection is required")
	}
	return c.channel.Send(ctx, frame)
}

func (c *Conn) ReceiveFrame(ctx context.Context) ([]byte, error) {
	if c == nil || c.channel == nil {
		return nil, eris.New("command channel connection is required")
	}
	return c.channel.Recv(ctx)
}

func (c *Conn) MaxSendFrameSize() int {
	if c == nil || c.channel == nil {
		return 0
	}
	return c.channel.MaxSendFrameSize()
}

func (c *Conn) Close() error {
	if c == nil || c.channel == nil {
		return nil
	}
	return c.channel.Close()
}
