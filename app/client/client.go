package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/settings"
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

func RunClient(ctx context.Context, cfg settings.Settings, args ConnectArgs) error {
	if args.Address == "" {
		return eris.New("connect address is required")
	}
	if strings.TrimSpace(args.Command) != "" {
		return eris.New("remote command execution is not supported yet")
	}

	conn, err := net.Dial("tcp", makeAddr(args.Address, cfg.Core.Port))
	if err != nil {
		return eris.Wrapf(err, "connect to %s", args.Address)
	}
	//TODO: implement comprehensive connection lifecycle
	// and integrate connection closing/termination with
	// logging and application error handling
	//nolint:errcheck
	defer conn.Close()
	log.Info("connected", "addr", conn.RemoteAddr())

	clientIdentity, err := trust.LookupClientIdentity(trust.DefaultClientIdentityPath)
	if err != nil {
		return err
	}

	established, err := session.Connect(ctx, conn, session.ClientConfig{
		ReferenceIdentity:   referenceIdentity(args.Address),
		Username:            localUsername(),
		ClientIdentity:      clientIdentity,
		VerifyServerHostKey: trust.KnownHostsHostKeyVerifier(trust.DefaultKnownHostsPath),
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}
	defer established.Close()

	log.Info("server identity", "fingerprint", established.Metadata().ServerHostKey.FingerprintSHA256())
	log.Info("authenticated session established", "session_protocol", "disabled")
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
