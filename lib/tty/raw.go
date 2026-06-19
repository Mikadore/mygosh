package tty

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rotisserie/eris"
	"golang.org/x/term"
)

type Size struct {
	Width  int
	Height int
}

type RawTTY struct {
	tty      *os.File
	resizes  <-chan Size
	oldState *term.State
	once     sync.Once
	err      error
}

func HookRaw(ctx context.Context, tty *os.File) (*RawTTY, error) {
	var rawTty RawTTY
	if ctx == nil {
		ctx = context.Background()
	}

	oldState, err := term.MakeRaw(int(tty.Fd()))
	if err != nil {
		return &rawTty, eris.Wrapf(err, "failed to make TTY %v", tty.Fd())
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	resizes := make(chan Size, 1)

	go func() {
		defer signal.Stop(sig)
		defer close(resizes)
		for {
			select {
			case <-sig:
				w, h, err := term.GetSize(int(tty.Fd()))
				if err == nil {
					select {
					case resizes <- Size{w, h}:
					default:
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	rawTty.tty = tty
	rawTty.resizes = resizes
	rawTty.oldState = oldState
	return &rawTty, nil
}

func (t *RawTTY) Read(p []byte) (int, error) {
	return t.tty.Read(p)
}

func (t *RawTTY) Write(p []byte) (int, error) {
	return t.tty.Write(p)
}

func (t *RawTTY) Resizes() <-chan Size {
	return t.resizes
}

func (t *RawTTY) Restore() error {
	t.once.Do(func() {
		t.err = eris.Wrap(term.Restore(int(t.tty.Fd()), t.oldState), "failed to restore TTY")
	})
	return t.err
}
