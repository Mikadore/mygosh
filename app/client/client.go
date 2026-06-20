package client

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/Mikadore/mygosh/app/root"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/establish"
	"github.com/rotisserie/eris"
)

type ConnectArgs struct {
	Target string
}

func RunClient(ctx context.Context, appRoot *root.Root, args ConnectArgs) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if appRoot == nil {
		return eris.New("project root is required")
	}
	if args.Target == "" {
		return eris.New("connect target is required")
	}
	logger := appRoot.Logger.With("command", "client")
	cfg := appRoot.Settings

	target, err := parseConnectTarget(args.Target)
	if err != nil {
		return err
	}

	clientIdentity, err := loadClientIdentity(defaultClientIdentityPath, logger)
	if err != nil {
		return err
	}
	knownHosts, knownHostsSource, err := loadKnownHosts(defaultKnownHostsPath, logger)
	if err != nil {
		return err
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target.dialAddress(cfg.Core.Port))
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return eris.Wrapf(err, "connect to %s", args.Target)
	}
	logger.Info("connected", "addr", conn.RemoteAddr())

	established, err := establish.Connect(ctx, conn, establish.ClientConfig{
		ReferenceIdentity:      target.referenceIdentity(),
		Username:               target.resolvedUsername(),
		ClientIdentityProvider: auth.StaticClientIdentityProvider(clientIdentity),
		VerifyServerHostKey:    knownHostsVerifier(knownHosts, knownHostsSource, logger),
		Logger:                 logger,
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}
	defer established.Close()

	logger.Info("server identity", "fingerprint", established.Auth.ServerHostKey.FingerprintSHA256())
	logger.Info("authenticated session established", "post_auth_mode", "reject-all")
	return established.Wait()
}

func localUsername() string {
	user := strings.TrimSpace(os.Getenv("USER"))
	if user == "" {
		return "unknown"
	}
	return user
}
