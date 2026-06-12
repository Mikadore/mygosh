package session

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/rotisserie/eris"
)

type ShellServer struct {
	transport *transport.Transport
	shell     string
}

func NewShellServer(transport *transport.Transport, shell string) *ShellServer {
	return &ShellServer{
		transport: transport,
		shell:     shell,
	}
}

func (s *ShellServer) Run(ctx context.Context) error {
	ctx = normalizeContext(ctx)

	stopWatchingContext := watchContextCancellation(ctx, s.transport)
	defer stopWatchingContext()

	req, err := s.receiveOpen()
	if err != nil {
		return preferContextError(ctx, err)
	}

	cmd := exec.CommandContext(ctx, s.shell)
	cmd.Env = sessionEnv(req)

	vtty, err := tty.CreateVTTY(tty.Size{Width: int(req.GetCols()), Height: int(req.GetRows())}, cmd)
	if err != nil {
		_ = s.transport.Send(&sessionpb.Envelope{
			Kind: &sessionpb.Envelope_Err{
				Err: &sessionpb.Error{Code: "pty-start-failed", Message: err.Error()},
			},
		})
		return eris.Wrap(err, "create server PTY")
	}
	//TODO: implement comprehensive application lifecycle
	// and integrate with logging and error handling
	//nolint:errcheck
	defer vtty.Close()

	if err := s.transport.Send(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_OpenOk{
			OpenOk: &sessionpb.OpenResponse{SessionId: "session-1"},
		},
	}); err != nil {
		return preferContextError(ctx, eris.Wrap(err, "send open response"))
	}

	errs := make(chan error, 2)
	go func() { errs <- s.forwardOutput(vtty, cmd) }()
	go func() { errs <- s.receiveInput(vtty) }()

	return preferContextError(ctx, <-errs)
}

func (s *ShellServer) receiveOpen() (*sessionpb.OpenRequest, error) {
	envelope, err := s.transport.Receive()
	if err != nil {
		return nil, eris.Wrap(err, "receive open request")
	}

	open, ok := envelope.Kind.(*sessionpb.Envelope_Open)
	if !ok {
		_ = s.transport.Send(&sessionpb.Envelope{
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

func (s *ShellServer) forwardOutput(vtty *tty.VTTY, cmd *exec.Cmd) error {
	buf := make([]byte, 4096)
	for {
		n, err := vtty.Read(buf)
		if n > 0 {
			if sendErr := s.transport.Send(&sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Data{
					Data: &sessionpb.Data{Data: buf[:n]},
				},
			}); sendErr != nil {
				return eris.Wrap(sendErr, "send PTY output")
			}
		}
		if err != nil {
			if terminalClosed(err) {
				code, waitErr := waitExit(cmd)
				if sendErr := s.transport.Send(&sessionpb.Envelope{
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

func (s *ShellServer) receiveInput(vtty *tty.VTTY) error {
	for {
		envelope, err := s.transport.Receive()
		if err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive client event")
		}

		switch kind := envelope.Kind.(type) {
		case *sessionpb.Envelope_Data:
			if err := writeFull(vtty, kind.Data.GetData()); err != nil {
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
			_ = s.transport.Send(&sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Err{
					Err: &sessionpb.Error{Code: "unexpected-event", Message: msg.Error()},
				},
			})
			return msg
		}
	}
}

func sessionEnv(req *sessionpb.OpenRequest) []string {
	env := os.Environ()
	if strings.TrimSpace(req.GetTerm()) != "" {
		env = append(env, "TERM="+req.GetTerm())
	}
	return env
}

func terminalClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EIO)
}

func waitExit(cmd *exec.Cmd) (int, error) {
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
