package command

import (
	"errors"
	"strings"

	commandprotocol "github.com/Mikadore/mygosh/lib/command"
	"github.com/rotisserie/eris"
	"golang.org/x/sys/unix"
)

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

type RemoteExitError struct {
	Code   int
	Cause  error
	silent bool
}

func (e *RemoteExitError) Error() string {
	if e == nil || e.Cause == nil {
		return "remote command failed"
	}
	return e.Cause.Error()
}

func (e *RemoteExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *RemoteExitError) ExitCode() int {
	if e == nil {
		return 255
	}
	return e.Code
}

func (e *RemoteExitError) Silent() bool {
	return e != nil && e.silent
}

func terminalResult(result commandprotocol.ExitResult) error {
	switch {
	case result.RuntimeFailure != "":
		return &RuntimeError{Message: result.RuntimeFailure}
	case result.Signal != "":
		return &ExitSignalError{Signal: result.Signal}
	case result.Status != 0:
		return &ExitStatusError{Status: result.Status}
	default:
		return nil
	}
}

func normalizeRemoteExit(err error) error {
	if err == nil {
		return nil
	}
	var status *ExitStatusError
	if errors.As(err, &status) {
		code := status.Status
		if code < 1 || code > 255 {
			code = 255
		}
		return &RemoteExitError{Code: code, Cause: err, silent: true}
	}
	var signal *ExitSignalError
	if errors.As(err, &signal) {
		number := unix.SignalNum(strings.ToUpper(signal.Signal))
		if number == 0 {
			return &RemoteExitError{Code: 255, Cause: err}
		}
		return &RemoteExitError{Code: 128 + int(number), Cause: err}
	}
	return &RemoteExitError{Code: 255, Cause: err}
}
