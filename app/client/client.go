package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/Mikadore/mygosh/app/commandchannel"
	"github.com/Mikadore/mygosh/app/config"
	"github.com/Mikadore/mygosh/app/root"
	"github.com/Mikadore/mygosh/lib/auth"
	commandprotocol "github.com/Mikadore/mygosh/lib/command"
	"github.com/Mikadore/mygosh/lib/establish"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/rotisserie/eris"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type ConnectArgs struct {
	Target      string
	Command     []string
	ForcePTY    bool
	DisablePTY  bool
	Environment []string
}

func RunClient(ctx context.Context, appRoot *root.Root, cfg config.Client, args ConnectArgs) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if appRoot == nil {
		return eris.New("project root is required")
	}
	if args.Target == "" {
		return eris.New("connect target is required")
	}
	if args.ForcePTY && args.DisablePTY {
		return eris.New("-t and -T cannot be used together")
	}
	if err := cfg.Validate(); err != nil {
		return eris.Wrap(err, "validate client config")
	}
	logger := appRoot.Audit.With("command", "client")

	target, err := parseConnectTarget(args.Target)
	if err != nil {
		return err
	}

	clientIdentity, err := loadClientIdentity(cfg.Identity.PrivateKey)
	if err != nil {
		return err
	}
	knownHosts, knownHostsSource, err := loadKnownHosts(cfg.Trust.KnownHosts)
	if err != nil {
		return err
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target.dialAddress(cfg.Connection.DefaultPort))
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
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}
	defer established.Close()

	logger.Info("server identity", "fingerprint", established.Auth.ServerHostKey.FingerprintSHA256())
	logger.Info("authenticated session established", "post_auth_mode", "command")

	channel, err := established.OpenChannel(ctx, commandprotocol.ChannelType, nil)
	if err != nil {
		return eris.Wrap(err, "open command channel")
	}
	frameConn, err := commandchannel.New(channel)
	if err != nil {
		return err
	}
	commandClient, err := commandprotocol.NewClient(frameConn)
	if err != nil {
		return err
	}
	defer commandClient.Close()

	request, localTerminal, err := buildStartRequest(args)
	if err != nil {
		return err
	}
	commandCtx, cancelCommand := context.WithCancelCause(ctx)
	defer cancelCommand(context.Canceled)
	stopOnCancel := context.AfterFunc(commandCtx, func() {
		_ = commandClient.Close()
	})
	defer stopOnCancel()

	var rawTTY *tty.RawTTY
	if request.PTY != nil && localTerminal {
		rawTTY, err = tty.HookRaw(commandCtx, os.Stdin)
		if err != nil {
			return err
		}
		defer rawTTY.Restore() //nolint:errcheck
	}

	if err := commandClient.Start(commandCtx, request, commandprotocol.OutputSink{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}); err != nil {
		return err
	}

	input, err := tty.NewPollReader(os.Stdin)
	if err != nil {
		return err
	}
	defer input.Close() //nolint:errcheck

	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := forwardInput(commandCtx, input, commandClient); err != nil && context.Cause(commandCtx) == nil {
			cancelCommand(err)
		}
	}()
	if rawTTY != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case size, ok := <-rawTTY.Resizes():
					if !ok {
						return
					}
					if err := commandClient.Resize(commandCtx, commandprotocol.WindowSize{
						Rows:    uint32(size.Height),
						Columns: uint32(size.Width),
					}); err != nil {
						cancelCommand(err)
						return
					}
				case <-commandCtx.Done():
					return
				}
			}
		}()
	}

	waitErr := commandClient.Wait()
	cancelCommand(waitErr)
	_ = input.Close()
	workers.Wait()
	return normalizeRemoteExit(waitErr)
}

func localUsername() string {
	user := strings.TrimSpace(os.Getenv("USER"))
	if user == "" {
		return "unknown"
	}
	return user
}

func buildStartRequest(args ConnectArgs) (commandprotocol.StartRequest, bool, error) {
	request := commandprotocol.StartRequest{}
	if len(args.Command) == 0 {
		request.Kind = commandprotocol.StartShell
	} else {
		request.Kind = commandprotocol.StartExec
		request.Command = strings.Join(args.Command, " ")
	}
	environment, err := requestedEnvironment(args.Environment)
	if err != nil {
		return commandprotocol.StartRequest{}, false, err
	}
	request.Environment = environment

	localTerminal := term.IsTerminal(int(os.Stdin.Fd()))
	usePTY := args.ForcePTY || (!args.DisablePTY && request.Kind == commandprotocol.StartShell && localTerminal)
	if usePTY {
		width, height := 80, 24
		if localTerminal {
			if terminalWidth, terminalHeight, sizeErr := term.GetSize(int(os.Stdin.Fd())); sizeErr == nil &&
				terminalWidth > 0 && terminalHeight > 0 {
				width, height = terminalWidth, terminalHeight
			}
		}
		terminal := strings.TrimSpace(os.Getenv("TERM"))
		if terminal == "" {
			terminal = "xterm-256color"
		}
		request.PTY = &commandprotocol.PTYRequest{
			Terminal: terminal,
			Rows:     uint32(height),
			Columns:  uint32(width),
		}
	}
	return request, localTerminal, nil
}

func requestedEnvironment(options []string) (map[string]string, error) {
	environment := make(map[string]string, len(options))
	for _, option := range options {
		name, value, explicit := strings.Cut(option, "=")
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, "=\x00") {
			return nil, eris.Errorf("invalid environment option %q", option)
		}
		if !explicit {
			var exists bool
			value, exists = os.LookupEnv(name)
			if !exists {
				return nil, eris.Errorf("local environment variable %q is not set", name)
			}
		}
		if strings.ContainsRune(value, '\x00') {
			return nil, eris.Errorf("environment variable %q contains NUL", name)
		}
		if _, exists := environment[name]; exists {
			return nil, eris.Errorf("environment variable %q was requested more than once", name)
		}
		environment[name] = value
	}
	return environment, nil
}

func forwardInput(ctx context.Context, input *tty.PollReader, client *commandprotocol.Client) error {
	buffer := make([]byte, 32<<10)
	for {
		n, err := input.Read(ctx, buffer)
		if n > 0 {
			if writeErr := client.WriteStdin(ctx, buffer[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, syscall.EIO) {
				closeErr := client.CloseStdin(ctx)
				if errors.Is(closeErr, context.Canceled) || errors.Is(closeErr, os.ErrClosed) {
					return nil
				}
				return closeErr
			}
			if errors.Is(err, os.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if errors.Is(err, syscall.EPIPE) {
				return nil
			}
			return err
		}
	}
}

type RemoteExitError struct {
	Code   int
	Cause  error
	silent bool
}

func (e *RemoteExitError) Error() string {
	if e == nil || e.Cause == nil {
		return "remote command failed"
	}
	return e.Cause.Error()
}

func (e *RemoteExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *RemoteExitError) ExitCode() int {
	if e == nil {
		return 255
	}
	return e.Code
}

func (e *RemoteExitError) Silent() bool {
	return e != nil && e.silent
}

func normalizeRemoteExit(err error) error {
	if err == nil {
		return nil
	}
	var status *commandprotocol.ExitStatusError
	if errors.As(err, &status) {
		code := status.Status
		if code < 1 || code > 255 {
			code = 255
		}
		return &RemoteExitError{Code: code, Cause: err, silent: true}
	}
	var signal *commandprotocol.ExitSignalError
	if errors.As(err, &signal) {
		number := unix.SignalNum(strings.ToUpper(signal.Signal))
		if number == 0 {
			return &RemoteExitError{Code: 255, Cause: err}
		}
		return &RemoteExitError{Code: 128 + int(number), Cause: err}
	}
	return &RemoteExitError{Code: 255, Cause: err}
}
