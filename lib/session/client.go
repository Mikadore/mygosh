package session

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/rotisserie/eris"
	"golang.org/x/term"
)

type ClientSession struct {
	transport *wire.Transport
	input     *os.File
	output    io.Writer
}

func NewClientSession(transport *wire.Transport, input *os.File, output io.Writer) *ClientSession {
	return &ClientSession{
		transport: transport,
		input:     input,
		output:    output,
	}
}

func (s *ClientSession) Run(ctx context.Context) error {
	raw, err := tty.HookRaw(ctx, s.input)
	if err != nil {
		return eris.Wrap(err, "hook raw terminal")
	}
	defer raw.Restore()

	size := currentTerminalSize(s.input)
	if err := s.transport.SendOpen(wire.OpenRequest{
		Term: terminalName(),
		Rows: uint16(size.Height),
		Cols: uint16(size.Width),
	}); err != nil {
		return eris.Wrap(err, "send open request")
	}

	if err := s.waitOpenOK(); err != nil {
		return err
	}

	errs := make(chan error, 3)
	go func() { errs <- s.forwardInput(raw) }()
	go func() { errs <- s.forwardResizes(ctx, raw) }()
	go func() { errs <- s.receiveOutput() }()

	return <-errs
}

func (s *ClientSession) waitOpenOK() error {
	event, err := s.transport.ReceiveEvent()
	if err != nil {
		return eris.Wrap(err, "receive open response")
	}

	switch event := event.(type) {
	case wire.OpenOKEvent:
		return nil
	case wire.ErrEvent:
		return eris.Errorf("server rejected open: %s", event.Error.Message)
	default:
		return eris.Errorf("expected open response, got %T", event)
	}
}

func (s *ClientSession) forwardInput(raw *tty.RawTTY) error {
	buf := make([]byte, 4096)
	for {
		n, err := raw.Read(buf)
		if n > 0 {
			if sendErr := s.transport.SendData(buf[:n]); sendErr != nil {
				return eris.Wrap(sendErr, "send terminal data")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return s.transport.SendClose(wire.Close{Reason: "stdin closed"})
			}
			return eris.Wrap(err, "read terminal")
		}
	}
}

func (s *ClientSession) forwardResizes(ctx context.Context, raw *tty.RawTTY) error {
	for {
		select {
		case size, ok := <-raw.Resizes():
			if !ok {
				return nil
			}
			if err := s.transport.SendResize(wire.Resize{
				Rows: uint16(size.Height),
				Cols: uint16(size.Width),
			}); err != nil {
				return eris.Wrap(err, "send terminal resize")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *ClientSession) receiveOutput() error {
	for {
		event, err := s.transport.ReceiveEvent()
		if err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive session event")
		}

		switch event := event.(type) {
		case wire.DataEvent:
			if err := writeFull(s.output, event.Bytes); err != nil {
				return eris.Wrap(err, "write terminal output")
			}
		case wire.ExitStatusEvent:
			if event.Status.Code == 0 {
				return nil
			}
			return eris.Errorf("remote process exited with status %d", event.Status.Code)
		case wire.CloseEvent:
			return nil
		case wire.ErrEvent:
			return eris.Errorf("server error: %s", event.Error.Message)
		default:
			return eris.Errorf("unexpected server event %T", event)
		}
	}
}

func currentTerminalSize(file *os.File) tty.Size {
	width, height, err := term.GetSize(int(file.Fd()))
	if err != nil || width <= 0 || height <= 0 {
		return tty.Size{Width: 80, Height: 24}
	}
	return tty.Size{Width: width, Height: height}
}

func terminalName() string {
	name := strings.TrimSpace(os.Getenv("TERM"))
	if name == "" {
		return "xterm"
	}
	return name
}

func writeFull(w io.Writer, p []byte) error {
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
