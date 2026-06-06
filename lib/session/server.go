package session

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/rotisserie/eris"
)

type ServerSession struct {
	transport *wire.Transport
	shell     string
}

func NewServerSession(transport *wire.Transport, shell string) *ServerSession {
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

	vtty, err := tty.CreateVTTY(tty.Size{Width: int(req.Cols), Height: int(req.Rows)}, cmd)
	if err != nil {
		_ = s.transport.SendErr(wire.ErrorPayload{Code: "pty-start-failed", Message: err.Error()})
		return eris.Wrap(err, "create server PTY")
	}
	defer vtty.Close()

	if err := s.transport.SendOpenOK(wire.OpenResponse{}); err != nil {
		return eris.Wrap(err, "send open response")
	}

	errs := make(chan error, 2)
	go func() { errs <- s.forwardOutput(vtty, cmd) }()
	go func() { errs <- s.receiveInput(vtty) }()

	return <-errs
}

func (s *ServerSession) receiveOpen() (wire.OpenRequest, error) {
	event, err := s.transport.ReceiveEvent()
	if err != nil {
		return wire.OpenRequest{}, eris.Wrap(err, "receive open request")
	}

	open, ok := event.(wire.OpenEvent)
	if !ok {
		_ = s.transport.SendErr(wire.ErrorPayload{Code: "expected-open", Message: "expected open request"})
		return wire.OpenRequest{}, eris.Errorf("expected open request, got %T", event)
	}

	req := open.Request
	if req.Rows == 0 {
		req.Rows = 24
	}
	if req.Cols == 0 {
		req.Cols = 80
	}
	return req, nil
}

func (s *ServerSession) forwardOutput(vtty *tty.VTTY, cmd *exec.Cmd) error {
	buf := make([]byte, 4096)
	for {
		n, err := vtty.Read(buf)
		if n > 0 {
			if sendErr := s.transport.SendData(buf[:n]); sendErr != nil {
				return eris.Wrap(sendErr, "send PTY output")
			}
		}
		if err != nil {
			if terminalClosed(err) {
				code, waitErr := waitExit(cmd)
				if sendErr := s.transport.SendExitStatus(wire.ExitStatus{Code: code}); sendErr != nil {
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
		event, err := s.transport.ReceiveEvent()
		if err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive client event")
		}

		switch event := event.(type) {
		case wire.DataEvent:
			if err := writeFull(vtty, event.Bytes); err != nil {
				return eris.Wrap(err, "write PTY input")
			}
		case wire.ResizeEvent:
			if err := vtty.Resize(tty.Size{Width: int(event.Resize.Cols), Height: int(event.Resize.Rows)}); err != nil {
				return eris.Wrap(err, "resize PTY")
			}
		case wire.CloseEvent:
			return nil
		default:
			msg := eris.Errorf("unexpected client event %T", event)
			_ = s.transport.SendErr(wire.ErrorPayload{Code: "unexpected-event", Message: msg.Error()})
			return msg
		}
	}
}

func sessionEnv(req wire.OpenRequest) []string {
	env := os.Environ()
	if strings.TrimSpace(req.Term) != "" {
		env = append(env, "TERM="+req.Term)
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
