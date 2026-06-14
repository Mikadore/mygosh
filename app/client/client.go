package client

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/settings"
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

const (
	demoServerHostSeed = "mygosh-demo-server-host-key-v1"
	demoClientSeed     = "mygosh-demo-client-key-v1"
)

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

	serverHostKey, err := demoEd25519Keypair(demoServerHostSeed)
	if err != nil {
		return err
	}

	clientIdentity, err := demoEd25519Keypair(demoClientSeed)
	if err != nil {
		return err
	}

	established, err := session.Connect(ctx, conn, session.ClientConfig{
		ReferenceIdentity:   referenceIdentity(args.Address),
		Username:            localUsername(),
		ClientIdentity:      clientIdentity,
		VerifyServerHostKey: auth.ExactHostKeyVerifier(referenceIdentity(args.Address), serverHostKey.PublicKey()),
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

func demoEd25519Keypair(seedText string) (keys.Keypair, error) {
	seed := sha256.Sum256([]byte(seedText))
	keypair, err := keys.GenerateEd25519FromSeed(seed[:])
	if err != nil {
		return keys.Keypair{}, eris.Wrap(err, "derive demo auth key")
	}
	return keypair, nil
}
