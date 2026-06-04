package main

import (
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/Mikadore/mygosh/internal/logging"
	"github.com/Mikadore/mygosh/internal/wire"
	"github.com/rotisserie/eris"
)

const listenAddr = "localhost:42022"

func main() {
	logger := slog.New(logging.NewPrettyHandler(os.Stderr, nil))

	if err := run(logger); err != nil {
		logger.Error("server failed", "err", eris.ToString(err, false))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return eris.Wrapf(err, "listen on %s", listenAddr)
	}
	defer listener.Close()
	logger.Info("listening", "addr", listener.Addr())

	conn, err := listener.Accept()
	if err != nil {
		return eris.Wrap(err, "accept connection")
	}
	defer conn.Close()
	logger.Info("accepted connection", "remote", conn.RemoteAddr())

	for {
		frame, err := wire.NewConn(conn).Receive()
		if err != nil {
			return eris.Wrap(err, "receive frame")
		}

		logger.Info(
			"received frame",
			"type", string(frame.Type),
			"bytes", len(frame.Payload),
			"text", printableString(frame.Payload),
			"hex", hexBytes(frame.Payload),
		)
	}
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
