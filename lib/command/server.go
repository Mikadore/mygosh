package command

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/Mikadore/mygosh/lib/command/commandpb"
	"github.com/rotisserie/eris"
)

const (
	genericStartRejectCode    = "start-rejected"
	genericStartRejectMessage = "command could not be started"
	genericRuntimeMessage     = "command terminated because of a protocol or runtime failure"
	outputDrainTimeout        = 5 * time.Second
	terminalSendTimeout       = 2 * time.Second
)

// Serve runs exactly one command protocol instance over conn.
func Serve(conn FrameConn, starter Starter) error {
	if err := validateFrameConn(conn); err != nil {
		return err
	}
	if starter == nil {
		return eris.New("command starter is required")
	}
	server := &server{
		conn:    conn,
		starter: starter,
	}
	defer conn.Close()
	return server.serve()
}

type server struct {
	conn    FrameConn
	starter Starter
	writeMu sync.Mutex
}

func (s *server) serve() error {
	frame, err := s.conn.ReceiveFrame(s.conn.Context())
	if err != nil {
		return eris.Wrap(err, "receive command start")
	}
	var first commandpb.ClientFrame
	if err := unmarshalMessage(frame, &first); err != nil {
		_ = s.sendStartResult(false)
		return protocolErrorf("invalid initial client frame: %v", err)
	}
	startFrame, ok := first.GetKind().(*commandpb.ClientFrame_Start)
	if !ok {
		_ = s.sendStartResult(false)
		return protocolErrorf("first client frame must be start")
	}
	request, err := decodeStart(startFrame.Start)
	if err != nil {
		_ = s.sendStartResult(false)
		return protocolErrorf("invalid start request: %v", err)
	}

	process, err := s.starter.Start(s.conn.Context(), request)
	if err != nil {
		_ = s.sendStartResult(false)
		return eris.Wrap(err, "start command")
	}
	if process == nil {
		_ = s.sendStartResult(false)
		return eris.New("command starter returned no running process")
	}
	if err := s.sendStartResult(true); err != nil {
		process.Terminate(err)
		_ = process.Wait()
		return eris.Wrap(err, "send command start acceptance")
	}

	inputCtx, cancelInput := context.WithCancelCause(s.conn.Context())
	defer cancelInput(context.Canceled)
	outputCtx, cancelOutput := context.WithCancelCause(s.conn.Context())
	defer cancelOutput(context.Canceled)

	outputs := make(chan error, 2)
	pendingOutputs := 1
	go s.copyOutput(outputCtx, process.Stdout(), false, outputs)
	if stderr := process.Stderr(); stderr != nil {
		pendingOutputs++
		go s.copyOutput(outputCtx, stderr, true, outputs)
	}

	inputResult := make(chan error, 1)
	go func() {
		inputResult <- s.receiveInput(inputCtx, process, request.PTY != nil)
	}()

	exitResult := make(chan ExitResult, 1)
	go func() {
		exitResult <- process.Wait()
	}()

	var (
		protocolFailure error
		processResult   ExitResult
		processExited   bool
	)
	fail := func(err error) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		if protocolFailure == nil {
			protocolFailure = err
			process.Terminate(err)
		}
	}

	for !processExited {
		select {
		case err := <-inputResult:
			inputResult = nil
			if context.Cause(inputCtx) == nil {
				fail(err)
			}
		case outputErr := <-outputs:
			pendingOutputs--
			if outputErr != nil && context.Cause(outputCtx) == nil {
				fail(eris.Wrap(outputErr, "forward command output"))
			}
		case processResult = <-exitResult:
			processExited = true
		case <-s.conn.Context().Done():
			fail(context.Cause(s.conn.Context()))
		}
	}
	cancelInput(nil)

	drainTimer := time.NewTimer(outputDrainTimeout)
	defer drainTimer.Stop()
	for pendingOutputs > 0 {
		select {
		case outputErr := <-outputs:
			pendingOutputs--
			if outputErr != nil && context.Cause(outputCtx) == nil {
				fail(eris.Wrap(outputErr, "drain command output"))
			}
		case <-drainTimer.C:
			fail(context.DeadlineExceeded)
			cancelOutput(context.DeadlineExceeded)
			_ = process.CloseOutput()
			pendingOutputs = 0
		case <-s.conn.Context().Done():
			fail(context.Cause(s.conn.Context()))
			cancelOutput(protocolFailure)
			_ = process.CloseOutput()
			pendingOutputs = 0
		}
	}

	if protocolFailure != nil {
		processResult = ExitResult{RuntimeFailure: genericRuntimeMessage}
	}
	sendCtx, cancelSend := context.WithTimeout(context.Background(), terminalSendTimeout)
	defer cancelSend()
	if err := s.sendExit(sendCtx, processResult); err != nil {
		return eris.Wrap(err, "send command exit")
	}
	return protocolFailure
}

func (s *server) receiveInput(ctx context.Context, process RunningProcess, hasPTY bool) error {
	stdinEOF := false
	for {
		frame, err := s.conn.ReceiveFrame(ctx)
		if err != nil {
			return err
		}
		var message commandpb.ClientFrame
		if err := unmarshalMessage(frame, &message); err != nil {
			return protocolErrorf("invalid client frame: %v", err)
		}
		switch kind := message.GetKind().(type) {
		case *commandpb.ClientFrame_Start:
			return protocolErrorf("duplicate start")
		case *commandpb.ClientFrame_Stdin:
			if stdinEOF {
				return protocolErrorf("stdin after EOF")
			}
			if err := process.WriteStdin(ctx, kind.Stdin.GetData()); err != nil {
				return eris.Wrap(err, "write process stdin")
			}
		case *commandpb.ClientFrame_StdinEof:
			if stdinEOF {
				return protocolErrorf("duplicate stdin EOF")
			}
			stdinEOF = true
			if err := process.CloseStdin(); err != nil {
				return eris.Wrap(err, "close process stdin")
			}
		case *commandpb.ClientFrame_WindowChange:
			if !hasPTY {
				return protocolErrorf("window change requires PTY")
			}
			if err := process.Resize(ctx, WindowSize{
				Rows:    kind.WindowChange.GetRows(),
				Columns: kind.WindowChange.GetColumns(),
			}); err != nil {
				return eris.Wrap(err, "resize process PTY")
			}
		default:
			return protocolErrorf("unsupported client frame %T", message.GetKind())
		}
	}
}

func (s *server) copyOutput(ctx context.Context, reader io.Reader, stderr bool, result chan<- error) {
	if reader == nil {
		result <- nil
		return
	}
	if closer, ok := reader.(io.Closer); ok {
		defer closer.Close() //nolint:errcheck
	}
	buffer := make([]byte, 32<<10)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			data := append([]byte(nil), buffer[:n]...)
			frames, chunkErr := chunkedFrames(data, s.conn.MaxSendFrameSize(), func(chunk []byte) *commandpb.ServerFrame {
				if stderr {
					return &commandpb.ServerFrame{
						Kind: &commandpb.ServerFrame_Stderr{
							Stderr: &commandpb.Stderr{Data: append([]byte(nil), chunk...)},
						},
					}
				}
				return &commandpb.ServerFrame{
					Kind: &commandpb.ServerFrame_Stdout{
						Stdout: &commandpb.Stdout{Data: append([]byte(nil), chunk...)},
					},
				}
			})
			if chunkErr != nil {
				result <- chunkErr
				return
			}
			for _, frame := range frames {
				if sendErr := s.sendEncoded(ctx, frame); sendErr != nil {
					result <- sendErr
					return
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				result <- nil
			} else {
				result <- err
			}
			return
		}
	}
}

func (s *server) sendStartResult(accepted bool) error {
	result := &commandpb.StartResult{Accepted: accepted}
	if !accepted {
		result.Code = genericStartRejectCode
		result.Message = genericStartRejectMessage
	}
	return s.sendMessage(s.conn.Context(), &commandpb.ServerFrame{
		Kind: &commandpb.ServerFrame_StartResult{StartResult: result},
	})
}

func (s *server) sendExit(ctx context.Context, result ExitResult) error {
	exit := &commandpb.Exit{}
	switch {
	case result.RuntimeFailure != "":
		exit.Result = &commandpb.Exit_RuntimeFailure{
			RuntimeFailure: &commandpb.RuntimeFailure{Message: result.RuntimeFailure},
		}
	case result.Signal != "":
		exit.Result = &commandpb.Exit_Signal{Signal: result.Signal}
	default:
		exit.Result = &commandpb.Exit_Status{Status: int32(result.Status)}
	}
	return s.sendMessage(ctx, &commandpb.ServerFrame{
		Kind: &commandpb.ServerFrame_Exit{Exit: exit},
	})
}

func (s *server) sendMessage(ctx context.Context, message *commandpb.ServerFrame) error {
	frame, err := marshalMessage(message, s.conn.MaxSendFrameSize())
	if err != nil {
		return err
	}
	return s.sendEncoded(ctx, frame)
}

func (s *server) sendEncoded(ctx context.Context, frame []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.SendFrame(ctx, frame)
}
