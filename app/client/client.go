package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/rotisserie/eris"
)

func makeAddr(addr string, port int) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil || len(p) == 0 {
		return net.JoinHostPort(addr, fmt.Sprintf("%d", port))
	} else {
		return addr
	}
}

func Run(cfg settings.Settings) error {
	logger := logging.NewLogger(os.Stderr, cfg.Log.Level, cfg.Log.JSON)
	if cfg.Connect.Address == "" {
		return eris.New("connect address is required")
	}

	conn, err := net.Dial("tcp", makeAddr(cfg.Connect.Address, cfg.Core.Port))
	if err != nil {
		return eris.Wrapf(err, "connect to %s", cfg.Connect.Address)
	}
	defer conn.Close()
	logger.Info("connected", "addr", conn.RemoteAddr())

	framed := wire.NewConn(conn)
	return forwardTTY(logger, framed)
}

func forwardTTY(logger *log.Logger, framed *wire.Conn) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	raw, err := tty.HookRaw(ctx, os.Stdin)
	if err != nil {
		return eris.Wrap(err, "hook raw terminal")
	}
	defer func() {
		if err := raw.Restore(); err != nil {
			logger.Warn("restore terminal failed", "err", err)
		}
	}()

	buff := make([]byte, 1024)
	for {
		n, err := raw.Read(buff)
		if err != nil {
			_ = framed.Send(wire.FrameErr, []byte(err.Error()))
			return eris.Wrap(err, "read terminal")
		}
		if err := framed.Send(wire.FrameData, buff[:n]); err != nil {
			return eris.Wrap(err, "send terminal frame")
		}
	}
}
