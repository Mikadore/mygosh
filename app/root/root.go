package root

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/settings"
)

type ShutdownFunc func(context.Context) error

type Root struct {
	Settings settings.Settings
	Logger   *slog.Logger
	Logging  *logging.Service

	mu        sync.Mutex
	shutdowns []ShutdownFunc
}

func New(cfg settings.Settings) (*Root, error) {
	loggingService, err := logging.NewService(cfg.Log)
	if err != nil {
		return nil, err
	}

	root := &Root{
		Settings: cfg,
		Logger:   loggingService.Logger(),
		Logging:  loggingService,
	}
	root.RegisterShutdown(func(context.Context) error {
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

	r.mu.Lock()
	shutdowns := append([]ShutdownFunc(nil), r.shutdowns...)
	r.mu.Unlock()

	var err error
	for i := len(shutdowns) - 1; i >= 0; i-- {
		err = errors.Join(err, shutdowns[i](ctx))
	}
	return err
}
