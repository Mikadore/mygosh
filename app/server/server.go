package server

import (
	"context"
	"net"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/Mikadore/mygosh/lib/trust"
	"github.com/rotisserie/eris"
)

var defaultAuthorizedKeysPaths = []string{
	"~/.mygosh/authorized_keys",
	"~/.ssh/authorized_keys",
}

func RunServer(ctx context.Context, cfg settings.Settings) error {
	addr := cfg.ListenAddress()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return eris.Wrapf(err, "listen on %s", addr)
	}
	//TODO: implement comprehensive connection lifecycle
	// and integrate connection closing/termination with
	// logging and application error handling
	//nolint:errcheck
	defer listener.Close()
	log.Info("listening", "addr", listener.Addr(), "shell", cfg.Core.Shell)

	conn, err := listener.Accept()
	if err != nil {
		return eris.Wrap(err, "accept connection")
	}
	//TODO: implement comprehensive connection lifecycle
	// and integrate connection closing/termination with
	// logging and application error handling
	//nolint:errcheck
	defer conn.Close()
	log.Info("accepted connection", "remote", conn.RemoteAddr())

	serverHostKey, err := trust.LookupHostKey(trust.DefaultHostKeyPath)
	if err != nil {
		return err
	}

	established, err := session.Accept(ctx, conn, session.ServerConfig{
		HostKey:         serverHostKey,
		AuthorizeClient: trust.AuthorizedKeysClientAuthorizer(defaultAuthorizedKeysPaths),
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}
	defer established.Close()

	meta := established.Metadata()
	log.Info("authenticated client", "username", meta.ClientIdentity.Username, "fingerprint", meta.ClientIdentity.PublicKey.FingerprintSHA256())
	log.Info("authenticated session established", "session_protocol", "disabled")
	return nil
}
