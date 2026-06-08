package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

type ConnectArgs struct {
	Address string
	Command string
}

func makeAddr(addr string, port int) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil || len(p) == 0 {
		return net.JoinHostPort(addr, fmt.Sprintf("%d", port))
	} else {
		return addr
	}
}

func RunClient(ctx context.Context, cfg settings.Settings, args ConnectArgs) error {
	if args.Address == "" {
		return eris.New("connect address is required")
	}
	if strings.TrimSpace(args.Command) != "" {
		return eris.New("remote command execution is not supported yet")
	}

	conn, err := net.Dial("tcp", makeAddr(args.Address, cfg.Core.Port))
	if err != nil {
		return eris.Wrapf(err, "connect to %s", args.Address)
	}
	defer conn.Close()
	log.Info("connected", "addr", conn.RemoteAddr())

	stream, err := transport.Handshake(conn, true)
	if err != nil {
		return eris.Wrap(err, "Handshake failed")
	}
	transport := transport.NewTransport(stream)
	return session.NewClientSession(transport, os.Stdin, os.Stdout).Run(ctx)
}
