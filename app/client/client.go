package client

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/rotisserie/eris"
)

func Run(cfg settings.Settings) error {
	logger := logging.NewLogger(os.Stderr, cfg.Log.Level, cfg.Log.JSON)
	if cfg.Connect.Address == "" {
		return eris.New("connect address is required")
	}

	conn, err := net.Dial("tcp", cfg.Connect.Address)
	if err != nil {
		return eris.Wrapf(err, "connect to %s", cfg.Connect.Address)
	}
	defer conn.Close()
	logger.Info("connected", "addr", conn.RemoteAddr())

	framed := wire.NewConn(conn)
	if cfg.Connect.Command != "" {
		return sendCommand(logger, framed, cfg.Connect.Command)
	}

	return forwardTTY(logger, framed)
}

func sendCommand(logger *slog.Logger, framed *wire.Conn, command string) error {
	payload := []byte(command)
	if err := framed.Send(wire.FrameData, payload); err != nil {
		return eris.Wrap(err, "send command frame")
	}
	logger.Info("sent frame", "type", string(wire.FrameData), "bytes", len(payload))
	return nil
}

func forwardTTY(logger *slog.Logger, framed *wire.Conn) error {
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
