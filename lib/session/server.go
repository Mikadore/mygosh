package session

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/Mikadore/mygosh/lib/transport/wirepb"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/rotisserie/eris"
)

type ServerSession struct {
	transport *transport.Transport
	shell     string
}

func NewServerSession(transport *transport.Transport, shell string) *ServerSession {
	return &ServerSession{
		transport: transport,
		shell:     shell,
	}
}

func (s *ServerSession) Run(ctx context.Context) error {
	req, err := s.receiveOpen()
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, s.shell)
	cmd.Env = sessionEnv(req)

	vtty, err := tty.CreateVTTY(tty.Size{Width: int(req.GetCols()), Height: int(req.GetRows())}, cmd)
	if err != nil {
		_ = s.transport.Send(&wirepb.Envelope{
			Kind: &wirepb.Envelope_Err{
				Err: &wirepb.Error{Code: "pty-start-failed", Message: err.Error()},
			},
		})
		return eris.Wrap(err, "create server PTY")
	}
	defer vtty.Close()

	if err := s.transport.Send(&wirepb.Envelope{
		Kind: &wirepb.Envelope_OpenOk{
			OpenOk: &wirepb.OpenResponse{SessionId: "session-1"},
		},
	}); err != nil {
		return eris.Wrap(err, "send open response")
	}

	errs := make(chan error, 2)
	go func() { errs <- s.forwardOutput(vtty, cmd) }()
	go func() { errs <- s.receiveInput(vtty) }()

	return <-errs
}

func (s *ServerSession) receiveOpen() (*wirepb.OpenRequest, error) {
	envelope, err := s.transport.Receive()
	if err != nil {
		return nil, eris.Wrap(err, "receive open request")
	}

	open, ok := envelope.Kind.(*wirepb.Envelope_Open)
	if !ok {
		_ = s.transport.Send(&wirepb.Envelope{
			Kind: &wirepb.Envelope_Err{
				Err: &wirepb.Error{Code: "expected-open", Message: "expected open request"},
			},
		})
		return nil, eris.Errorf("expected open request, got %T", envelope.Kind)
	}

	req := open.Open
	if req == nil {
		req = &wirepb.OpenRequest{}
	}
	if req.GetRows() == 0 {
		req.Rows = 24
	}
	if req.GetCols() == 0 {
		req.Cols = 80
	}
	return req, nil
}

func (s *ServerSession) forwardOutput(vtty *tty.VTTY, cmd *exec.Cmd) error {
	buf := make([]byte, 4096)
	for {
		n, err := vtty.Read(buf)
		if n > 0 {
			if sendErr := s.transport.Send(&wirepb.Envelope{
				Kind: &wirepb.Envelope_Data{
					Data: &wirepb.Data{Data: buf[:n]},
				},
			}); sendErr != nil {
				return eris.Wrap(sendErr, "send PTY output")
			}
		}
		if err != nil {
			if terminalClosed(err) {
				code, waitErr := waitExit(cmd)
				if sendErr := s.transport.Send(&wirepb.Envelope{
					Kind: &wirepb.Envelope_ExitStatus{
						ExitStatus: &wirepb.ExitStatus{Code: int32(code)},
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

func (s *ServerSession) receiveInput(vtty *tty.VTTY) error {
	for {
		envelope, err := s.transport.Receive()
		if err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive client event")
		}

		switch kind := envelope.Kind.(type) {
		case *wirepb.Envelope_Data:
			if err := writeFull(vtty, kind.Data.GetData()); err != nil {
				return eris.Wrap(err, "write PTY input")
			}
		case *wirepb.Envelope_Resize:
			if err := vtty.Resize(tty.Size{Width: int(kind.Resize.GetCols()), Height: int(kind.Resize.GetRows())}); err != nil {
				return eris.Wrap(err, "resize PTY")
			}
		case *wirepb.Envelope_Close:
			return nil
		default:
			msg := eris.Errorf("unexpected client event %T", kind)
			_ = s.transport.Send(&wirepb.Envelope{
				Kind: &wirepb.Envelope_Err{
					Err: &wirepb.Error{Code: "unexpected-event", Message: msg.Error()},
				},
			})
			return msg
		}
	}
}

func sessionEnv(req *wirepb.OpenRequest) []string {
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
