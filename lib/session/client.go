package session

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/rotisserie/eris"
	"golang.org/x/term"
)

type TerminalClient struct {
	transport *transport.Transport
	input     *os.File
	output    io.Writer
}

func NewTerminalClient(transport *transport.Transport, input *os.File, output io.Writer) *TerminalClient {
	return &TerminalClient{
		transport: transport,
		input:     input,
		output:    output,
	}
}

func (s *TerminalClient) Run(ctx context.Context) error {
	ctx = normalizeContext(ctx)

	stopWatchingContext := watchContextCancellation(ctx, s.transport)
	defer stopWatchingContext()

	raw, err := tty.HookRaw(ctx, s.input)
	if err != nil {
		return eris.Wrap(err, "hook raw terminal")
	}
	//TODO: implement comprehensive application lifecycle
	// and integrate with logging and error handling
	//nolint:errcheck
	defer raw.Restore()

	size := currentTerminalSize(s.input)
	if err := s.transport.Send(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_Open{
			Open: &sessionpb.OpenRequest{
				Term: terminalName(),
				Rows: uint32(size.Height),
				Cols: uint32(size.Width),
			},
		},
	}); err != nil {
		return preferContextError(ctx, eris.Wrap(err, "send open request"))
	}

	if err := s.waitOpenOK(); err != nil {
		return preferContextError(ctx, err)
	}

	errs := make(chan error, 3)
	go func() { errs <- s.forwardInput(raw) }()
	go func() { errs <- s.forwardResizes(ctx, raw) }()
	go func() { errs <- s.receiveOutput() }()

	return preferContextError(ctx, <-errs)
}

func (s *TerminalClient) waitOpenOK() error {
	envelope, err := s.transport.Receive()
	if err != nil {
		return eris.Wrap(err, "receive open response")
	}

	switch kind := envelope.Kind.(type) {
	case *sessionpb.Envelope_OpenOk:
		return nil
	case *sessionpb.Envelope_Err:
		return eris.Errorf("server rejected open: %s", kind.Err.GetMessage())
	default:
		return eris.Errorf("expected open response, got %T", kind)
	}
}

func (s *TerminalClient) forwardInput(raw *tty.RawTTY) error {
	buf := make([]byte, 4096)
	for {
		n, err := raw.Read(buf)
		if n > 0 {
			if sendErr := s.transport.Send(&sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Data{
					Data: &sessionpb.Data{Data: buf[:n]},
				},
			}); sendErr != nil {
				return eris.Wrap(sendErr, "send terminal data")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return s.transport.Send(&sessionpb.Envelope{
					Kind: &sessionpb.Envelope_Close{
						Close: &sessionpb.Close{Reason: "stdin closed"},
					},
				})
			}
			return eris.Wrap(err, "read terminal")
		}
	}
}

func (s *TerminalClient) forwardResizes(ctx context.Context, raw *tty.RawTTY) error {
	for {
		select {
		case size, ok := <-raw.Resizes():
			if !ok {
				return nil
			}
			if err := s.transport.Send(&sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Resize{
					Resize: &sessionpb.Resize{
						Rows: uint32(size.Height),
						Cols: uint32(size.Width),
					},
				},
			}); err != nil {
				return eris.Wrap(err, "send terminal resize")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *TerminalClient) receiveOutput() error {
	for {
		envelope, err := s.transport.Receive()
		if err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive session event")
		}

		switch kind := envelope.Kind.(type) {
		case *sessionpb.Envelope_Data:
			if err := writeFull(s.output, kind.Data.GetData()); err != nil {
				return eris.Wrap(err, "write terminal output")
			}
		case *sessionpb.Envelope_ExitStatus:
			code := kind.ExitStatus.GetCode()
			if code == 0 {
				return nil
			}
			return eris.Errorf("remote process exited with status %d", code)
		case *sessionpb.Envelope_Close:
			return nil
		case *sessionpb.Envelope_Err:
			return eris.Errorf("server error: %s", kind.Err.GetMessage())
		default:
			return eris.Errorf("unexpected server event %T", kind)
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
