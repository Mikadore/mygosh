package tty

import (
	"context"
	"os"
	"os/signal"
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
}

func HookRaw(ctx context.Context, tty *os.File) (*RawTTY, error) {
	var rawTty RawTTY

	oldState, err := term.MakeRaw(int(tty.Fd()))
	if err != nil {
		return &rawTty, eris.Wrapf(err, "failed to make TTY %v", tty.Fd())
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	resizes := make(chan Size)

	go func() {
		for {
			select {
			case <-sig:
				w, h, err := term.GetSize(int(tty.Fd()))
				if err == nil {
					resizes <- Size{w, h}
				}
			case <-ctx.Done():
				signal.Stop(sig)
				close(sig)
				close(resizes)
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
	return eris.Wrap(term.Restore(int(t.tty.Fd()), t.oldState), "Failed to restore TTY")
}
