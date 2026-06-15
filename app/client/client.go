package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Mikadore/mygosh/app/root"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/connection"
	"github.com/Mikadore/mygosh/lib/trust"
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

func RunClient(ctx context.Context, appRoot *root.Root, args ConnectArgs) error {
	if appRoot == nil {
		return eris.New("project root is required")
	}
	if args.Address == "" {
		return eris.New("connect address is required")
	}
	if strings.TrimSpace(args.Command) != "" {
		return eris.New("remote command execution is not supported yet")
	}

	logger := appRoot.Logger.With("command", "client")
	cfg := appRoot.Settings

	conn, err := net.Dial("tcp", makeAddr(args.Address, cfg.Core.Port))
	if err != nil {
		return eris.Wrapf(err, "connect to %s", args.Address)
	}
	//TODO: implement comprehensive connection lifecycle
	// and integrate connection closing/termination with
	// logging and application error handling
	//nolint:errcheck
	defer conn.Close()
	logger.Info("connected", "addr", conn.RemoteAddr())

	clientIdentity, err := trust.LookupClientIdentityWithLogger(trust.DefaultClientIdentityPath, logger)
	if err != nil {
		return err
	}

	established, err := connection.Connect(ctx, conn, connection.ClientConfig{
		ReferenceIdentity:      referenceIdentity(args.Address),
		Username:               localUsername(),
		ClientIdentityProvider: auth.StaticClientIdentityProvider(auth.NewKeypairSigner(clientIdentity)),
		VerifyServerHostKey:    trust.KnownHostsHostKeyVerifierWithLogger(trust.DefaultKnownHostsPath, logger),
		Logger:                 logger,
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}
	defer established.Close()

	logger.Info("server identity", "fingerprint", established.Auth.ServerHostKey.FingerprintSHA256())
	logger.Info("authenticated session established", "session_protocol", "disabled")
	return nil
}

func referenceIdentity(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "" {
		return host
	}
	return addr
}

func localUsername() string {
	user := strings.TrimSpace(os.Getenv("USER"))
	if user == "" {
		return "unknown"
	}
	return user
}
