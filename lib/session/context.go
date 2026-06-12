package session

import (
	"context"
	"io"
	"sync"
)

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func watchContextCancellation(ctx context.Context, closer io.Closer) func() {
	ctx = normalizeContext(ctx)

	stopCh := make(chan struct{})
	var once sync.Once

	go func() {
		select {
		case <-ctx.Done():
			_ = closer.Close()
		case <-stopCh:
		}
	}()

	return func() {
		once.Do(func() {
			close(stopCh)
		})
	}
}

func preferContextError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
