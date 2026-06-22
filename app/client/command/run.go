package command

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"syscall"

	commandprotocol "github.com/Mikadore/mygosh/lib/command"
	"github.com/Mikadore/mygosh/lib/tty"
	"github.com/rotisserie/eris"
)

type Options struct {
	Stdin         *os.File
	Stdout        io.Writer
	Stderr        io.Writer
	LocalTerminal bool
}

func Run(ctx context.Context, conn commandprotocol.FrameConn, request commandprotocol.StartRequest, options Options) error {
	ctx = normalizeContext(ctx)
	logger := slog.Default().With("component", "client-command")
	if options.Stdin == nil {
		return eris.New("command stdin is required")
	}
	if options.Stdout == nil {
		return eris.New("command stdout is required")
	}
	if options.Stderr == nil {
		return eris.New("command stderr is required")
	}

	commandClient, err := newClient(conn)
	if err != nil {
		return err
	}
	defer commandClient.closeClient() //nolint:errcheck

	commandCtx, cancelCommand := context.WithCancelCause(ctx)
	defer cancelCommand(context.Canceled)
	stopOnCancel := context.AfterFunc(commandCtx, func() {
		_ = commandClient.closeClient()
	})
	defer stopOnCancel()

	var rawTTY *tty.RawTTY
	if request.PTY != nil && options.LocalTerminal {
		rawTTY, err = tty.HookRaw(commandCtx, options.Stdin)
		if err != nil {
			return err
		}
		logger.Debug("local terminal entered raw mode")
		defer rawTTY.Restore() //nolint:errcheck
	}

	logger.Debug(
		"sending command start",
		"kind", startKindName(request.Kind),
		"pty", request.PTY != nil,
		"environment_count", len(request.Environment),
	)
	if err := commandClient.start(commandCtx, request, outputSink{
		stdout: options.Stdout,
		stderr: options.Stderr,
	}); err != nil {
		return err
	}
	logger.Debug("command start accepted", "kind", startKindName(request.Kind), "pty", request.PTY != nil)

	input, err := tty.NewPollReader(options.Stdin)
	if err != nil {
		return err
	}
	defer input.Close() //nolint:errcheck

	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := forwardInput(commandCtx, input, commandClient); err != nil && context.Cause(commandCtx) == nil {
			cancelCommand(err)
		}
	}()
	if rawTTY != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case size, ok := <-rawTTY.Resizes():
					if !ok {
						return
					}
					if err := commandClient.resize(commandCtx, commandprotocol.WindowSize{
						Rows:    uint32(size.Height),
						Columns: uint32(size.Width),
					}); err != nil {
						cancelCommand(err)
						return
					}
					logger.Debug(
						"sent terminal resize",
						"rows", size.Height,
						"columns", size.Width,
					)
				case <-commandCtx.Done():
					return
				}
			}
		}()
	}

	waitErr := commandClient.wait()
	cancelCommand(waitErr)
	_ = input.Close()
	workers.Wait()
	logger.Debug("command completed", "err", waitErr)
	return normalizeRemoteExit(waitErr)
}

func forwardInput(ctx context.Context, input *tty.PollReader, client *client) error {
	buffer := make([]byte, 32<<10)
	for {
		n, err := input.Read(ctx, buffer)
		if n > 0 {
			if writeErr := client.writeStdin(ctx, buffer[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, syscall.EIO) {
				closeErr := client.closeStdin(ctx)
				if errors.Is(closeErr, context.Canceled) || errors.Is(closeErr, os.ErrClosed) {
					return nil
				}
				return closeErr
			}
			if errors.Is(err, os.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if errors.Is(err, syscall.EPIPE) {
				return nil
			}
			return err
		}
	}
}

func startKindName(kind commandprotocol.StartKind) string {
	switch kind {
	case commandprotocol.StartShell:
		return "shell"
	case commandprotocol.StartExec:
		return "exec"
	default:
		return "unknown"
	}
}
