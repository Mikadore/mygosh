package server

import (
	"io"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/Mikadore/mygosh/internal/logging"
	"github.com/Mikadore/mygosh/internal/settings"
	"github.com/Mikadore/mygosh/internal/wire"
	"github.com/rotisserie/eris"
)

func Run(cfg settings.Settings) error {
	logger := logging.NewLogger(os.Stderr, cfg.Log.Level, cfg.Log.JSON)
	addr := cfg.ListenAddress()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return eris.Wrapf(err, "listen on %s", addr)
	}
	defer listener.Close()
	logger.Info("listening", "addr", listener.Addr(), "shell", cfg.Core.Shell)

	conn, err := listener.Accept()
	if err != nil {
		return eris.Wrap(err, "accept connection")
	}
	defer conn.Close()
	logger.Info("accepted connection", "remote", conn.RemoteAddr())

	framed := wire.NewConn(conn)
	for {
		frame, err := framed.Receive()
		if err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive frame")
		}

		logFrame(logger, frame)
	}
}

func logFrame(logger *slog.Logger, frame wire.Frame) {
	logger.Info(
		"received frame",
		"type", string(frame.Type),
		"bytes", len(frame.Payload),
		"text", printableString(frame.Payload),
		"hex", hexBytes(frame.Payload),
	)
}

func printableString(payload []byte) string {
	var out strings.Builder
	for _, b := range payload {
		if b >= 0x20 && b <= 0x7e {
			out.WriteByte(b)
			continue
		}
		out.WriteByte('.')
	}
	return out.String()
}

func hexBytes(payload []byte) string {
	parts := make([]string, len(payload))
	for i, b := range payload {
		const digits = "0123456789abcdef"
		parts[i] = string([]byte{digits[b>>4], digits[b&0x0f]})
	}
	return strings.Join(parts, " ")
}
