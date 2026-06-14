package session

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/rotisserie/eris"
)

const (
	defaultHandshakeTimeout = 5 * time.Second
	defaultAuthTimeout      = 10 * time.Second
)

type deadlineCloser interface {
	io.Closer
	SetDeadline(time.Time) error
}

type connRuntime struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	mu        sync.Mutex
	target    io.Closer
	timer     *time.Timer
	closeOnce sync.Once
}

func newConnRuntime(parent context.Context, target io.Closer) *connRuntime {
	parent = normalizeContext(parent)

	ctx, cancel := context.WithCancelCause(parent)
	runtime := &connRuntime{
		ctx:    ctx,
		cancel: cancel,
		target: target,
	}
	go func() {
		<-runtime.ctx.Done()
		_ = runtime.closeTarget()
	}()
	return runtime
}

func (r *connRuntime) setTarget(target io.Closer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.target = target
}

func (r *connRuntime) runWithTimeout(timeout time.Duration, fn func() error) error {
	if err := context.Cause(r.ctx); err != nil {
		return err
	}

	if err := r.startTimer(timeout); err != nil {
		return err
	}
	defer r.stopTimer()

	err := fn()
	if cause := context.Cause(r.ctx); cause != nil {
		return cause
	}
	return err
}

func (r *connRuntime) startTimer(timeout time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.target == nil {
		return eris.New("runtime has no active target")
	}
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	if timeout <= 0 {
		return nil
	}

	r.timer = time.AfterFunc(timeout, func() {
		r.cancel(context.DeadlineExceeded)
		_ = r.closeTarget()
	})
	return nil
}

func (r *connRuntime) stopTimer() {
	r.mu.Lock()
	timer := r.timer
	r.timer = nil
	r.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
}

func (r *connRuntime) currentTarget() io.Closer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.target
}

func (r *connRuntime) closeTarget() error {
	r.stopTimer()

	var err error
	r.closeOnce.Do(func() {
		target := r.currentTarget()
		if target == nil {
			return
		}
		if deadlineTarget, ok := target.(deadlineCloser); ok {
			_ = deadlineTarget.SetDeadline(time.Now())
		}
		err = target.Close()
	})
	return err
}

func (r *connRuntime) Close() error {
	r.cancel(context.Canceled)
	return r.closeTarget()
}

func (r *connRuntime) wrapError(err error, message string) error {
	if cause := context.Cause(r.ctx); cause != nil {
		return eris.Wrap(cause, message)
	}
	if err == nil {
		return nil
	}
	return eris.Wrap(err, message)
}

func resolveTimeout(actual time.Duration, fallback time.Duration) time.Duration {
	if actual == 0 {
		return fallback
	}
	return actual
}
