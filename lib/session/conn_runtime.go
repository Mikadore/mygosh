package session

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/Mikadore/mygosh/lib/logging"
	charmlog "github.com/charmbracelet/log"
	"github.com/rotisserie/eris"
)

type deadlineCloser interface {
	io.Closer
	SetDeadline(time.Time) error
}

type Runtime struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	logger *charmlog.Logger

	mu        sync.Mutex
	target    io.Closer
	timer     *time.Timer
	closeOnce sync.Once
}

func NewRuntime(parent context.Context, target io.Closer, logger *charmlog.Logger) *Runtime {
	parent = normalizeContext(parent)

	ctx, cancel := context.WithCancelCause(parent)
	runtime := &Runtime{
		ctx:    ctx,
		cancel: cancel,
		target: target,
		logger: logging.Resolve(logger),
	}
	go func() {
		<-runtime.ctx.Done()
		_ = runtime.closeTarget()
	}()
	return runtime
}

func (r *Runtime) Context() context.Context {
	return r.ctx
}

func (r *Runtime) SetTarget(target io.Closer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.target = target
}

func (r *Runtime) RunWithTimeout(phase string, timeout time.Duration, fn func() error) error {
	if err := context.Cause(r.ctx); err != nil {
		return err
	}

	if err := r.startTimer(phase, timeout); err != nil {
		return err
	}
	defer r.stopTimer()

	err := fn()
	if cause := context.Cause(r.ctx); cause != nil {
		return cause
	}
	return err
}

func (r *Runtime) startTimer(phase string, timeout time.Duration) error {
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
		r.logger.Info("connection phase timed out", "phase", phase, "timeout", timeout)
		r.cancel(context.DeadlineExceeded)
		_ = r.closeTarget()
	})
	return nil
}

func (r *Runtime) stopTimer() {
	r.mu.Lock()
	timer := r.timer
	r.timer = nil
	r.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
}

func (r *Runtime) currentTarget() io.Closer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.target
}

func (r *Runtime) closeTarget() error {
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

func (r *Runtime) Close() error {
	r.cancel(context.Canceled)
	return r.closeTarget()
}

func (r *Runtime) Fail(cause error) error {
	if cause == nil {
		cause = context.Canceled
	}
	r.cancel(cause)
	return r.closeTarget()
}

func (r *Runtime) WrapError(err error, message string) error {
	if cause := context.Cause(r.ctx); cause != nil {
		return eris.Wrap(cause, message)
	}
	if err == nil {
		return nil
	}
	return eris.Wrap(err, message)
}
