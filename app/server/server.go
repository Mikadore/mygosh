package server

import (
	"context"
	"net"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

var staticServerKeypair = keys.MustParseKeypairBase64(
	"bXlnb3NoLXByaXZhdGUta2V5LXYxAAAABngyNTUxOQAAACDTsZU23gLTnfEZuTrZ4nmElhwUwR5sKgOWtUvr2o3laAAAACDdNf3zpMwLg6OsnTLfuRittrBU0X9DQAw0XvLjDYXO+AAAAAA=",
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

	stream, err := transport.HandshakeServer(conn, staticServerKeypair)
	if err != nil {
		return eris.Wrap(err, "Handshake Failed")
	}
	transport := transport.NewTransport(stream)
	return session.NewServerSession(transport, cfg.Core.Shell).Run(ctx)
}
