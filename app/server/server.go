package server

import (
	"context"
	"io"
	"net"
	"strings"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/rotisserie/eris"
)

func RunServer(ctx context.Context, cfg settings.Settings) error {
	addr := cfg.ListenAddress()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return eris.Wrapf(err, "listen on %s", addr)
	}
	defer listener.Close()
	log.Info("listening", "addr", listener.Addr(), "shell", cfg.Core.Shell)

	conn, err := listener.Accept()
	if err != nil {
		return eris.Wrap(err, "accept connection")
	}
	defer conn.Close()
	log.Info("accepted connection", "remote", conn.RemoteAddr())

	stream, err := wire.Handshake(conn, false)
	if err != nil {
		return eris.Wrap(err, "Handshake Failed")
	}
	for {
		frame, err := stream.Receive()
		if err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive frame")
		}

		logFrame(frame)
	}
}

func logFrame(frame []byte) {
	log.Info(
		"received frame",
		"bytes", len(frame),
		"text", printableString(frame),
		"hex", hexBytes(frame),
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
