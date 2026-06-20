//go:build linux || darwin || freebsd || openbsd || netbsd

package tty

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/rotisserie/eris"
	"golang.org/x/sys/unix"
)

// PollReader reads from a duplicated descriptor and can always be interrupted
// through its private cancellation pipe. Closing it never closes the caller's
// original input descriptor.
type PollReader struct {
	input   *os.File
	cancelR *os.File
	cancelW *os.File

	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
}

func NewPollReader(input *os.File) (*PollReader, error) {
	if input == nil {
		return nil, eris.New("input file is required")
	}
	duplicate, err := unix.Dup(int(input.Fd()))
	if err != nil {
		return nil, eris.Wrap(err, "duplicate input descriptor")
	}
	unix.CloseOnExec(duplicate)
	cancelR, cancelW, err := os.Pipe()
	if err != nil {
		_ = unix.Close(duplicate)
		return nil, eris.Wrap(err, "create input cancellation pipe")
	}
	return &PollReader{
		input:   os.NewFile(uintptr(duplicate), input.Name()+"-command-input"),
		cancelR: cancelR,
		cancelW: cancelW,
	}, nil
}

func (r *PollReader) Read(ctx context.Context, buffer []byte) (int, error) {
	if r == nil {
		return 0, os.ErrClosed
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return 0, os.ErrClosed
	}
	inputFD := int32(r.input.Fd())
	cancelFD := int32(r.cancelR.Fd())
	r.mu.Unlock()

	stop := context.AfterFunc(ctx, r.wake)
	defer stop()

	pollFDs := []unix.PollFd{
		{Fd: inputFD, Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR},
		{Fd: cancelFD, Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR},
	}
	for {
		_, err := unix.Poll(pollFDs, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, eris.Wrap(err, "poll command input")
		}
		if pollFDs[1].Revents != 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			return 0, os.ErrClosed
		}
		if pollFDs[0].Revents != 0 {
			n, readErr := r.input.Read(buffer)
			if n == 0 && readErr == nil {
				readErr = io.EOF
			}
			return n, readErr
		}
	}
}

func (r *PollReader) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		r.wake()
		closeErr = errors.Join(r.input.Close(), r.cancelR.Close(), r.cancelW.Close())
	})
	return closeErr
}

func (r *PollReader) wake() {
	if r == nil || r.cancelW == nil {
		return
	}
	_, _ = r.cancelW.Write([]byte{1})
}
