package server

import (
	"context"

	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

type ShellDemo struct {
	transport *transport.Transport
	shell     string
}

func NewShellDemo(messageTransport *transport.Transport, shell string) *ShellDemo {
	return &ShellDemo{
		transport: messageTransport,
		shell:     shell,
	}
}

func (d *ShellDemo) Run(ctx context.Context) error {
	_ = ctx
	_ = d
	return eris.New("shell demo is not wired into the generic session multiplexer yet")
}
