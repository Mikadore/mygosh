package establish

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/rotisserie/eris"
)

type deadlineCloser interface {
	io.Closer
	SetDeadline(time.Time) error
}

type lifecyclePhase string

const (
	lifecycleAccepted         lifecyclePhase = "accepted"
	lifecycleHandshaking      lifecyclePhase = "handshaking"
	lifecycleAuthPending      lifecyclePhase = "auth-pending"
	lifecyclePostAuthStarting lifecyclePhase = "post-auth-starting"
	lifecycleActive           lifecyclePhase = "active"
	lifecycleClosing          lifecyclePhase = "closing"
	lifecycleClosed           lifecyclePhase = "closed"
)

type runtime struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	logger *slog.Logger

	mu       sync.Mutex
	owner    io.Closer
	phase    lifecyclePhase
	timer    *time.Timer
	terminal error
}

func newRuntime(parent context.Context, owner io.Closer, role string) *runtime {
	parent = normalizeContext(parent)

	ctx, cancel := context.WithCancelCause(parent)
	runtime := &runtime{
		ctx:    ctx,
		cancel: cancel,
		owner:  owner,
		phase:  lifecycleAccepted,
		logger: slog.Default().With("component", "establish", "role", role),
	}

	go func() {
		<-runtime.ctx.Done()
		_ = runtime.closeCurrentOwner()
	}()

	return runtime
}

func (r *runtime) Context() context.Context {
	return r.ctx
}

func (r *runtime) SetOwner(owner io.Closer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.owner = owner
}

func (r *runtime) Release() {
	r.stopTimer()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.owner = nil
	if r.phase != lifecycleClosing && r.phase != lifecycleClosed {
		r.phase = lifecycleActive
	}
}

func (r *runtime) SetPhase(phase lifecyclePhase) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.phase = phase
}

func (r *runtime) RunWithTimeout(phase lifecyclePhase, timeout time.Duration, fn func() error) error {
	if err := context.Cause(r.ctx); err != nil {
		return err
	}

	r.SetPhase(phase)
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

func (r *runtime) startTimer(phase lifecyclePhase, timeout time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.owner == nil {
		return eris.New("runtime has no active owner")
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
		_ = r.Fail(context.DeadlineExceeded)
	})
	return nil
}

func (r *runtime) stopTimer() {
	r.mu.Lock()
	timer := r.timer
	r.timer = nil
	r.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
}

func (r *runtime) closeCurrentOwner() error {
	r.stopTimer()

	r.mu.Lock()
	owner := r.owner
	r.owner = nil
	phase := r.phase
	if phase == lifecycleClosing {
		r.phase = lifecycleClosed
	}
	r.mu.Unlock()

	if owner == nil {
		return nil
	}
	if deadlineOwner, ok := owner.(deadlineCloser); ok {
		_ = deadlineOwner.SetDeadline(time.Now())
	}
	if err := owner.Close(); err != nil {
		r.logger.Debug("connection owner cleanup failed", "phase", phase, "err", err)
		return err
	}
	return nil
}

func (r *runtime) Close() error {
	return r.Fail(context.Canceled)
}

func (r *runtime) Fail(cause error) error {
	if cause == nil {
		cause = context.Canceled
	}

	r.mu.Lock()
	if r.terminal == nil {
		r.terminal = cause
	}
	r.phase = lifecycleClosing
	r.mu.Unlock()

	r.cancel(cause)
	return r.closeCurrentOwner()
}

func (r *runtime) WrapError(err error, message string) error {
	if cause := context.Cause(r.ctx); cause != nil {
		return eris.Wrap(cause, message)
	}
	if err == nil {
		return nil
	}
	return eris.Wrap(err, message)
}
