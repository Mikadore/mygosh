package client

import (
	"context"
	"io"
	"os"

	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

type TerminalDemo struct {
	transport *transport.Transport
	input     *os.File
	output    io.Writer
}

func NewTerminalDemo(messageTransport *transport.Transport, input *os.File, output io.Writer) *TerminalDemo {
	return &TerminalDemo{
		transport: messageTransport,
		input:     input,
		output:    output,
	}
}

func (d *TerminalDemo) Run(ctx context.Context) error {
	_ = ctx
	_ = d
	return eris.New("terminal demo is not wired into the generic session multiplexer yet")
}
