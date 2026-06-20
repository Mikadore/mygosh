package command

import (
	"context"
	"io"

	"github.com/rotisserie/eris"
)

type StartKind uint8

const (
	StartShell StartKind = iota + 1
	StartExec
)

type PTYRequest struct {
	Terminal string
	Rows     uint32
	Columns  uint32
}

type StartRequest struct {
	Kind        StartKind
	Command     string
	PTY         *PTYRequest
	Environment map[string]string
}

func cloneStartRequest(request StartRequest) StartRequest {
	if request.PTY != nil {
		pty := *request.PTY
		request.PTY = &pty
	}
	request.Environment = cloneEnvironment(request.Environment)
	return request
}

func cloneEnvironment(environment map[string]string) map[string]string {
	copy := make(map[string]string, len(environment))
	for name, value := range environment {
		copy[name] = value
	}
	return copy
}

type WindowSize struct {
	Rows    uint32
	Columns uint32
}

type OutputSink struct {
	Stdout io.Writer
	Stderr io.Writer
}

type ExitResult struct {
	Status         int
	Signal         string
	RuntimeFailure string
}

// RunningProcess is installed only after a child has successfully started and
// an owner is already responsible for waiting and cleanup.
type RunningProcess interface {
	Stdout() io.Reader
	Stderr() io.Reader
	WriteStdin(ctx context.Context, data []byte) error
	CloseStdin() error
	Resize(ctx context.Context, size WindowSize) error
	Wait() ExitResult
	Terminate(cause error)
	CloseOutput() error
}

type Starter interface {
	Start(ctx context.Context, request StartRequest) (RunningProcess, error)
}

type StarterFunc func(ctx context.Context, request StartRequest) (RunningProcess, error)

func (f StarterFunc) Start(ctx context.Context, request StartRequest) (RunningProcess, error) {
	if f == nil {
		return nil, eris.New("command starter is required")
	}
	return f(ctx, cloneStartRequest(request))
}

type StartRejectedError struct {
	Code    string
	Message string
}

func (e *StartRejectedError) Error() string {
	if e == nil {
		return "command start rejected"
	}
	if e.Message == "" {
		return "command start rejected: " + e.Code
	}
	return "command start rejected: " + e.Message
}

type ExitStatusError struct {
	Status int
}

func (e *ExitStatusError) Error() string {
	if e == nil {
		return "remote command exited unsuccessfully"
	}
	return eris.Errorf("remote command exited with status %d", e.Status).Error()
}

type ExitSignalError struct {
	Signal string
}

func (e *ExitSignalError) Error() string {
	if e == nil {
		return "remote command terminated by signal"
	}
	return "remote command terminated by signal " + e.Signal
}

type RuntimeError struct {
	Message string
}

func (e *RuntimeError) Error() string {
	if e == nil || e.Message == "" {
		return "remote command failed"
	}
	return "remote command failed: " + e.Message
}

type ProtocolError struct {
	Message string
}

func (e *ProtocolError) Error() string {
	if e == nil {
		return "command protocol error"
	}
	return "command protocol error: " + e.Message
}

func protocolErrorf(format string, args ...any) error {
	return &ProtocolError{Message: eris.Errorf(format, args...).Error()}
}
