package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/rotisserie/eris"
)

const (
	demoServerHostSeed = "mygosh-demo-server-host-key-v1"
	demoClientSeed     = "mygosh-demo-client-key-v1"
)

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

	serverHostKey, err := demoEd25519Keypair(demoServerHostSeed)
	if err != nil {
		return err
	}

	authorizedClient, err := demoEd25519Keypair(demoClientSeed)
	if err != nil {
		return err
	}

	established, err := session.EstablishServer(conn, session.ServerConfig{
		HostKey: serverHostKey,
		AuthorizeClient: func(principal session.ClientPrincipal) error {
			if principal.Service != "shell" {
				return eris.Errorf("unsupported service %q", principal.Service)
			}
			authorizedPublicKey := authorizedClient.PublicKey()
			if principal.PublicKey.Algorithm != authorizedPublicKey.Algorithm || !bytes.Equal(principal.PublicKey.Bytes, authorizedPublicKey.Bytes) {
				return eris.New("client public key is not authorized")
			}
			return nil
		},
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}

	meta := established.Metadata()
	log.Info("authenticated client", "username", meta.ClientPrincipal.Username, "fingerprint", meta.ClientPrincipal.PublicKey.FingerprintSHA256())
	return session.NewShellServer(established.Transport(), cfg.Core.Shell).Run(ctx)
}

func demoEd25519Keypair(seedText string) (keys.Keypair, error) {
	seed := sha256.Sum256([]byte(seedText))
	keypair, err := keys.GenerateEd25519FromSeed(seed[:])
	if err != nil {
		return keys.Keypair{}, eris.Wrap(err, "derive demo auth key")
	}
	return keypair, nil
}
