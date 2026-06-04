package client

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/Mikadore/mygosh/lib/wire"
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

	conn, err := net.Dial("tcp", makeAddr(args.Address, cfg.Core.Port))
	if err != nil {
		return eris.Wrapf(err, "connect to %s", args.Address)
	}
	defer conn.Close()
	log.Info("connected", "addr", conn.RemoteAddr())

	stream, err := wire.Handshake(conn, true)
	if err != nil {
		return eris.Wrap(err, "Handshake failed")
	}
	return forwardTTY(ctx, stream)
}

func forwardTTY(ctx context.Context, framed *wire.NoiseStream) error {

	raw, err := tty.HookRaw(ctx, os.Stdin)
	if err != nil {
		return eris.Wrap(err, "hook raw terminal")
	}
	defer func() {
		if err := raw.Restore(); err != nil {
			log.Warn("restore terminal failed", "err", err)
		}
	}()

	buff := make([]byte, 1024)
	for {
		n, err := raw.Read(buff)
		if err != nil {
			_ = framed.Send( []byte(err.Error()))
			return eris.Wrap(err, "read terminal")
		}
		if err := framed.Send( buff[:n]); err != nil {
			return eris.Wrap(err, "send terminal frame")
		}
	}
}
