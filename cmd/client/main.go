package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mikadore/mygosh/internal/logging"
	"github.com/Mikadore/mygosh/internal/tty"
	"github.com/Mikadore/mygosh/internal/wire"
	"github.com/rotisserie/eris"
)

const serverAddr = "localhost:42022"

func main() {
	logger := slog.New(logging.NewPrettyHandler(os.Stderr, nil))

	if err := run(logger); err != nil {
		logger.Error("client failed", "err", eris.ToString(err, false))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL) 
	defer stop()
	
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return eris.Wrapf(err, "connect to %s", serverAddr)
	}
	defer conn.Close()
	logger.Info("connected", "addr", conn.RemoteAddr())

	framed := wire.NewConn(conn)
	raw, err := tty.HookRaw(ctx, os.Stdin)
	defer raw.Restore()

	buff := make([]byte, 1024)
	for {
		var	frameType wire.FrameType
		var payload []byte
		
		n, err := raw.Read(buff)
		if err == nil {
			frameType = wire.FrameData
			payload = buff[:n]
		} else {
			frameType = wire.FrameErr
			payload = []byte(err.Error())
		}
		framed.Send(frameType, payload)
	}
}
