package root

import (
	"context"
	"errors"
	"sync"

	charmlog "github.com/charmbracelet/log"

	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/settings"
)

type ShutdownFunc func(context.Context) error

type Root struct {
	Settings settings.Settings
	Logger   *charmlog.Logger

	mu        sync.Mutex
	shutdowns []ShutdownFunc
}

func New(cfg settings.Settings) *Root {
	return &Root{
		Settings: cfg,
		Logger:   logging.New(cfg.Log),
	}
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
