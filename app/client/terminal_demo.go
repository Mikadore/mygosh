package client

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/service"
	"github.com/Mikadore/mygosh/lib/service/servicepb"
	sessionmux "github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/rotisserie/eris"
	"golang.org/x/term"
)

type TerminalDemo struct {
	session *sessionmux.Session
	command string
	input   *os.File
	output  io.Writer
	logging *logging.Service
}

func NewTerminalDemo(sess *sessionmux.Session, command string, input *os.File, output io.Writer, loggingService *logging.Service) *TerminalDemo {
	return &TerminalDemo{
		session: sess,
		command: command,
		input:   input,
		output:  output,
		logging: loggingService,
	}
}

func (d *TerminalDemo) Run(ctx context.Context) (runErr error) {
	ctx = normalizeDemoContext(ctx)
	if d == nil || d.session == nil {
		return eris.New("client session is required")
	}
	if d.input == nil {
		return eris.New("terminal input is required")
	}
	if d.output == nil {
		return eris.New("terminal output is required")
	}
	if strings.TrimSpace(d.command) == "" {
		return eris.New("remote command is required")
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	sessionErrCh := make(chan error, 1)
	go func() {
		sessionErrCh <- d.session.Run(runCtx, nil)
	}()
	if err := d.session.WaitUntilRunning(runCtx); err != nil {
		return eris.Wrap(err, "start client session")
	}

	channelHandler := newTerminalChannelHandler()
	channel, err := d.session.OpenChannelWithHandler(runCtx, service.ChannelTypeSession, nil, channelHandler)
	if err != nil {
		return eris.Wrap(err, "open terminal channel")
	}
	defer channel.Close() //nolint:errcheck

	size := currentTerminalSize(d.input)
	ptyPayload, err := service.MarshalPayload(&servicepb.PtyRequest{
		Term: terminalName(),
		Rows: uint32(size.Height),
		Cols: uint32(size.Width),
	})
	if err != nil {
		return err
	}
	if err := sendRequiredRequest(runCtx, channel, service.RequestTypePTY, ptyPayload); err != nil {
		return eris.Wrap(err, "request remote PTY")
	}

	execPayload, err := service.MarshalPayload(&servicepb.ExecRequest{Command: d.command})
	if err != nil {
		return err
	}
	if err := sendRequiredRequest(runCtx, channel, service.RequestTypeExec, execPayload); err != nil {
		return eris.Wrap(err, "start remote command")
	}

	rawCtx, cancelRaw := context.WithCancel(runCtx)
	defer cancelRaw()

	raw, err := tty.HookRaw(rawCtx, d.input)
	if err != nil {
		return eris.Wrap(err, "enter raw terminal mode")
	}
	if d.logging != nil {
		d.logging.SetConsoleEnabled(false)
		defer d.logging.SetConsoleEnabled(true)
	}
	defer func() {
		runErr = errors.Join(runErr, raw.Restore())
	}()

	outputErrCh := make(chan error, 1)
	auxErrCh := make(chan error, 2)
	go func() { outputErrCh <- receiveTerminalOutput(runCtx, channel, d.output) }()
	go func() { auxErrCh <- forwardTerminalInput(runCtx, channel, raw) }()
	go func() { auxErrCh <- forwardTerminalResizes(rawCtx, channel, raw) }()

	for {
		select {
		case err := <-outputErrCh:
			if err != nil {
				return err
			}
			status, err := channelHandler.waitExitStatus(runCtx, sessionErrCh)
			if err != nil {
				return err
			}
			if err := channel.Close(); err != nil {
				return eris.Wrap(err, "close terminal channel")
			}
			if status != 0 {
				return eris.Errorf("remote process exited with status %d", status)
			}
			return nil
		case err := <-auxErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
		case err := <-sessionErrCh:
			if err == nil {
				return eris.New("session ended before the remote terminal closed")
			}
			return eris.Wrap(err, "run client session")
		case <-runCtx.Done():
			return context.Cause(runCtx)
		}
	}
}

type terminalExitResult struct {
	code int32
	err  error
}

type terminalChannelHandler struct {
	once   sync.Once
	result chan terminalExitResult
}

func newTerminalChannelHandler() *terminalChannelHandler {
	return &terminalChannelHandler{result: make(chan terminalExitResult, 1)}
}

func (h *terminalChannelHandler) OnRequest(_ context.Context, _ *sessionmux.Channel, req sessionmux.ChannelRequest) sessionmux.ChannelResponse {
	if req.Type != service.RequestTypeExitStatus {
		return sessionmux.ChannelResponse{
			Code:    "unsupported-channel-request",
			Message: "unsupported client channel request",
		}
	}

	var status servicepb.ExitStatus
	if err := service.UnmarshalPayload(req.Payload, &status); err != nil {
		h.finish(terminalExitResult{err: eris.Wrap(err, "decode remote exit status")})
		return sessionmux.ChannelResponse{
			Code:    "invalid-exit-status",
			Message: "invalid exit status",
		}
	}

	h.finish(terminalExitResult{code: status.GetCode()})
	return sessionmux.ChannelResponse{OK: true}
}

func (h *terminalChannelHandler) OnEOF(_ context.Context, _ *sessionmux.Channel) {
	h.finish(terminalExitResult{err: eris.New("remote terminal closed without an exit status")})
}

func (h *terminalChannelHandler) OnClose(_ context.Context, _ *sessionmux.Channel) {
	h.finish(terminalExitResult{err: eris.New("remote terminal closed without an exit status")})
}

func (h *terminalChannelHandler) finish(result terminalExitResult) {
	h.once.Do(func() {
		h.result <- result
	})
}

func (h *terminalChannelHandler) waitExitStatus(ctx context.Context, sessionErrCh <-chan error) (int32, error) {
	select {
	case result := <-h.result:
		return result.code, result.err
	case err := <-sessionErrCh:
		if err == nil {
			return 0, eris.New("session ended before receiving the remote exit status")
		}
		return 0, eris.Wrap(err, "run client session")
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	}
}

func sendRequiredRequest(ctx context.Context, channel *sessionmux.Channel, requestType string, payload []byte) error {
	response, err := channel.SendRequest(ctx, requestType, payload, true)
	if err != nil {
		return err
	}
	if response == nil {
		return eris.Errorf("%s request returned no response", requestType)
	}
	if !response.OK {
		return eris.Errorf("%s request rejected (%s): %s", requestType, response.Code, response.Message)
	}
	return nil
}

func forwardTerminalInput(ctx context.Context, channel *sessionmux.Channel, input io.Reader) error {
	buffer := make([]byte, 4096)
	for {
		n, err := input.Read(buffer)
		if n > 0 {
			if sendErr := channel.Send(ctx, buffer[:n]); sendErr != nil {
				return eris.Wrap(sendErr, "send terminal input")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return channel.CloseWrite()
			}
			return eris.Wrap(err, "read terminal input")
		}
	}
}

func forwardTerminalResizes(ctx context.Context, channel *sessionmux.Channel, raw *tty.RawTTY) error {
	for {
		select {
		case size, ok := <-raw.Resizes():
			if !ok {
				return nil
			}
			payload, err := service.MarshalPayload(&servicepb.TerminalSize{
				Rows: uint32(size.Height),
				Cols: uint32(size.Width),
			})
			if err != nil {
				return err
			}
			if _, err := channel.SendRequest(ctx, service.RequestTypeWindowChange, payload, false); err != nil {
				return eris.Wrap(err, "send terminal resize")
			}
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

func receiveTerminalOutput(ctx context.Context, channel *sessionmux.Channel, output io.Writer) error {
	for {
		frame, err := channel.Recv(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return eris.Wrap(err, "receive terminal output")
		}
		if err := writeFull(output, frame); err != nil {
			return eris.Wrap(err, "write terminal output")
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

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func normalizeDemoContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
