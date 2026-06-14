package client

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/rotisserie/eris"
	"golang.org/x/term"
)

type TerminalDemo struct {
	transport *transport.Transport
	input     *os.File
	output    io.Writer
}

func NewTerminalDemo(messageTransport *transport.Transport, input *os.File, output io.Writer) *TerminalDemo {
	return &TerminalDemo{
		transport: messageTransport,
		input:     input,
		output:    output,
	}
}

func (d *TerminalDemo) Run(ctx context.Context) error {
	ctx = clientNormalizeContext(ctx)

	stopWatchingContext := clientWatchContextCancellation(ctx, d.transport)
	defer stopWatchingContext()

	raw, err := tty.HookRaw(ctx, d.input)
	if err != nil {
		return eris.Wrap(err, "hook raw terminal")
	}
	defer raw.Restore() //nolint:errcheck

	size := clientCurrentTerminalSize(d.input)
	if err := transport.SendProto(d.transport, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_Open{
			Open: &sessionpb.OpenRequest{
				Term: clientTerminalName(),
				Rows: uint32(size.Height),
				Cols: uint32(size.Width),
			},
		},
	}); err != nil {
		return clientPreferContextError(ctx, eris.Wrap(err, "send open request"))
	}

	if err := d.waitOpenOK(); err != nil {
		return clientPreferContextError(ctx, err)
	}

	errs := make(chan error, 3)
	go func() { errs <- d.forwardInput(raw) }()
	go func() { errs <- d.forwardResizes(ctx, raw) }()
	go func() { errs <- d.receiveOutput() }()

	return clientPreferContextError(ctx, <-errs)
}

func (d *TerminalDemo) waitOpenOK() error {
	var envelope sessionpb.Envelope
	if err := transport.ReceiveProto(d.transport, &envelope); err != nil {
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

func (d *TerminalDemo) forwardInput(raw *tty.RawTTY) error {
	buf := make([]byte, 4096)
	for {
		n, err := raw.Read(buf)
		if n > 0 {
			if sendErr := transport.SendProto(d.transport, &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Data{
					Data: &sessionpb.Data{Data: buf[:n]},
				},
			}); sendErr != nil {
				return eris.Wrap(sendErr, "send terminal data")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return transport.SendProto(d.transport, &sessionpb.Envelope{
					Kind: &sessionpb.Envelope_Close{
						Close: &sessionpb.Close{Reason: "stdin closed"},
					},
				})
			}
			return eris.Wrap(err, "read terminal")
		}
	}
}

func (d *TerminalDemo) forwardResizes(ctx context.Context, raw *tty.RawTTY) error {
	for {
		select {
		case size, ok := <-raw.Resizes():
			if !ok {
				return nil
			}
			if err := transport.SendProto(d.transport, &sessionpb.Envelope{
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

func (d *TerminalDemo) receiveOutput() error {
	for {
		var envelope sessionpb.Envelope
		if err := transport.ReceiveProto(d.transport, &envelope); err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive session event")
		}

		switch kind := envelope.Kind.(type) {
		case *sessionpb.Envelope_Data:
			if err := clientWriteFull(d.output, kind.Data.GetData()); err != nil {
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

func clientCurrentTerminalSize(file *os.File) tty.Size {
	width, height, err := term.GetSize(int(file.Fd()))
	if err != nil || width <= 0 || height <= 0 {
		return tty.Size{Width: 80, Height: 24}
	}
	return tty.Size{Width: width, Height: height}
}

func clientTerminalName() string {
	name := strings.TrimSpace(os.Getenv("TERM"))
	if name == "" {
		return "xterm"
	}
	return name
}

func clientWriteFull(w io.Writer, p []byte) error {
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

func clientNormalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func clientWatchContextCancellation(ctx context.Context, closer io.Closer) func() {
	ctx = clientNormalizeContext(ctx)

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

func clientPreferContextError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
