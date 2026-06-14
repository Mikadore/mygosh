package server

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/rotisserie/eris"
)

type ShellDemo struct {
	transport *transport.Transport
	shell     string
}

func NewShellDemo(messageTransport *transport.Transport, shell string) *ShellDemo {
	return &ShellDemo{
		transport: messageTransport,
		shell:     shell,
	}
}

func (d *ShellDemo) Run(ctx context.Context) error {
	ctx = serverNormalizeContext(ctx)

	stopWatchingContext := serverWatchContextCancellation(ctx, d.transport)
	defer stopWatchingContext()

	req, err := d.receiveOpen()
	if err != nil {
		return serverPreferContextError(ctx, err)
	}

	cmd := exec.CommandContext(ctx, d.shell)
	cmd.Env = shellDemoEnv(req)

	vtty, err := tty.CreateVTTY(tty.Size{Width: int(req.GetCols()), Height: int(req.GetRows())}, cmd)
	if err != nil {
		_ = transport.SendProto(d.transport, &sessionpb.Envelope{
			Kind: &sessionpb.Envelope_Err{
				Err: &sessionpb.Error{Code: "pty-start-failed", Message: err.Error()},
			},
		})
		return eris.Wrap(err, "create server PTY")
	}
	defer vtty.Close() //nolint:errcheck

	if err := transport.SendProto(d.transport, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_OpenOk{
			OpenOk: &sessionpb.OpenResponse{SessionId: "session-1"},
		},
	}); err != nil {
		return serverPreferContextError(ctx, eris.Wrap(err, "send open response"))
	}

	errs := make(chan error, 2)
	go func() { errs <- d.forwardOutput(vtty, cmd) }()
	go func() { errs <- d.receiveInput(vtty) }()

	return serverPreferContextError(ctx, <-errs)
}

func (d *ShellDemo) receiveOpen() (*sessionpb.OpenRequest, error) {
	var envelope sessionpb.Envelope
	if err := transport.ReceiveProto(d.transport, &envelope); err != nil {
		return nil, eris.Wrap(err, "receive open request")
	}

	open, ok := envelope.Kind.(*sessionpb.Envelope_Open)
	if !ok {
		_ = transport.SendProto(d.transport, &sessionpb.Envelope{
			Kind: &sessionpb.Envelope_Err{
				Err: &sessionpb.Error{Code: "expected-open", Message: "expected open request"},
			},
		})
		return nil, eris.Errorf("expected open request, got %T", envelope.Kind)
	}

	req := open.Open
	if req == nil {
		req = &sessionpb.OpenRequest{}
	}
	if req.GetRows() == 0 {
		req.Rows = 24
	}
	if req.GetCols() == 0 {
		req.Cols = 80
	}
	return req, nil
}

func (d *ShellDemo) forwardOutput(vtty *tty.VTTY, cmd *exec.Cmd) error {
	buf := make([]byte, 4096)
	for {
		n, err := vtty.Read(buf)
		if n > 0 {
			if sendErr := transport.SendProto(d.transport, &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Data{
					Data: &sessionpb.Data{Data: buf[:n]},
				},
			}); sendErr != nil {
				return eris.Wrap(sendErr, "send PTY output")
			}
		}
		if err != nil {
			if shellDemoTerminalClosed(err) {
				code, waitErr := shellDemoWaitExit(cmd)
				if sendErr := transport.SendProto(d.transport, &sessionpb.Envelope{
					Kind: &sessionpb.Envelope_ExitStatus{
						ExitStatus: &sessionpb.ExitStatus{Code: int32(code)},
					},
				}); sendErr != nil {
					return eris.Wrap(sendErr, "send exit status")
				}
				if waitErr != nil {
					return eris.Wrap(waitErr, "wait for PTY process")
				}
				return nil
			}
			return eris.Wrap(err, "read PTY output")
		}
	}
}

func (d *ShellDemo) receiveInput(vtty *tty.VTTY) error {
	for {
		var envelope sessionpb.Envelope
		if err := transport.ReceiveProto(d.transport, &envelope); err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive client event")
		}

		switch kind := envelope.Kind.(type) {
		case *sessionpb.Envelope_Data:
			if err := serverWriteFull(vtty, kind.Data.GetData()); err != nil {
				return eris.Wrap(err, "write PTY input")
			}
		case *sessionpb.Envelope_Resize:
			if err := vtty.Resize(tty.Size{Width: int(kind.Resize.GetCols()), Height: int(kind.Resize.GetRows())}); err != nil {
				return eris.Wrap(err, "resize PTY")
			}
		case *sessionpb.Envelope_Close:
			return nil
		default:
			msg := eris.Errorf("unexpected client event %T", kind)
			_ = transport.SendProto(d.transport, &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Err{
					Err: &sessionpb.Error{Code: "unexpected-event", Message: msg.Error()},
				},
			})
			return msg
		}
	}
}

func shellDemoEnv(req *sessionpb.OpenRequest) []string {
	env := os.Environ()
	if strings.TrimSpace(req.GetTerm()) != "" {
		env = append(env, "TERM="+req.GetTerm())
	}
	return env
}

func shellDemoTerminalClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EIO)
}

func shellDemoWaitExit(cmd *exec.Cmd) (int, error) {
	err := cmd.Wait()
	if err == nil {
		return 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 1, err
}

func serverWriteFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func serverNormalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func serverWatchContextCancellation(ctx context.Context, closer io.Closer) func() {
	ctx = serverNormalizeContext(ctx)

	stopCh := make(chan struct{})
	var once sync.Once

	go func() {
		select {
		case <-ctx.Done():
			_ = closer.Close()
		case <-stopCh:
		}
	}()

	return func() {
		once.Do(func() {
			close(stopCh)
		})
	}
}

func serverPreferContextError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
