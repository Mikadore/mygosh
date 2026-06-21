package root

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/Mikadore/mygosh/app/logging"
)

type ShutdownFunc func(context.Context) error

type Root struct {
	Audit   *slog.Logger
	Logging *logging.Service

	mu        sync.Mutex
	shutdowns []ShutdownFunc

	shutdownOnce sync.Once
	shutdownErr  error
}

func New(cfg logging.Config) (*Root, error) {
	loggingService, err := logging.NewService(cfg)
	if err != nil {
		return nil, err
	}

	previousDiagnostics := slog.Default()
	slog.SetDefault(loggingService.Diagnostics())

	root := &Root{
		Audit:   loggingService.Audit(),
		Logging: loggingService,
	}
	root.RegisterShutdown(func(context.Context) error {
		if slog.Default() == loggingService.Diagnostics() {
			slog.SetDefault(previousDiagnostics)
		}
		return loggingService.Close()
	})
	return root, nil
}

func (r *Root) RegisterShutdown(fn ShutdownFunc) {
	if fn == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.shutdowns = append(r.shutdowns, fn)
}

func (r *Root) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}

	r.shutdownOnce.Do(func() {
		r.mu.Lock()
		shutdowns := append([]ShutdownFunc(nil), r.shutdowns...)
		r.mu.Unlock()

		for i := len(shutdowns) - 1; i >= 0; i-- {
			r.shutdownErr = errors.Join(r.shutdownErr, shutdowns[i](ctx))
		}
	})
	return r.shutdownErr
}
