package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/app/config"
	"github.com/stretchr/testify/require"
)

func TestConnectionAdmissionEnforcesAndReleasesLimits(t *testing.T) {
	admission := newConnectionAdmission(2, 1)
	require.True(t, admission.acquire("192.0.2.1"))
	require.False(t, admission.acquire("192.0.2.1"))
	require.True(t, admission.acquire("192.0.2.2"))
	require.False(t, admission.acquire("192.0.2.3"))

	admission.release("192.0.2.1")
	require.True(t, admission.acquire("192.0.2.3"))
}

func TestRunDaemonReleasesAdmissionSlots(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	release := make(chan struct{})
	var started atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- runDaemon(ctx, listener, config.ServerDaemon{
			MaxConnections:      1,
			MaxConnectionsPerIP: 1,
			ShutdownTimeout:     time.Second,
		}, slog.New(slog.DiscardHandler), func(context.Context, net.Conn, string) error {
			started.Add(1)
			<-release
			return nil
		})
	}()

	first, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	require.Eventually(t, func() bool { return started.Load() == 1 }, time.Second, 10*time.Millisecond)

	second, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, second.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = second.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, second.Close())

	close(release)
	require.NoError(t, first.Close())
	require.Eventually(t, func() bool {
		third, dialErr := net.Dial("tcp", listener.Addr().String())
		if dialErr != nil {
			return false
		}
		_ = third.Close()
		return started.Load() >= 2
	}, time.Second, 20*time.Millisecond)

	cancel()
	require.NoError(t, <-result)
}

func TestRunDaemonContainsPanicsAndAcceptsNextConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())

	var calls atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- runDaemon(ctx, listener, config.ServerDaemon{
			MaxConnections:      2,
			MaxConnectionsPerIP: 2,
			ShutdownTimeout:     time.Second,
		}, slog.New(slog.DiscardHandler), func(context.Context, net.Conn, string) error {
			if calls.Add(1) == 1 {
				panic("test panic")
			}
			return nil
		})
	}()

	for range 2 {
		conn, dialErr := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, dialErr)
		require.NoError(t, conn.Close())
		require.Eventually(t, func() bool { return calls.Load() >= 1 }, time.Second, 10*time.Millisecond)
	}
	require.Eventually(t, func() bool { return calls.Load() == 2 }, time.Second, 10*time.Millisecond)

	cancel()
	require.NoError(t, <-result)
}

func TestNormalizedSourceIPUnmapsIPv4(t *testing.T) {
	require.Equal(t, "192.0.2.4", normalizedSourceIP(&net.TCPAddr{
		IP:   net.ParseIP("::ffff:192.0.2.4"),
		Port: 42022,
	}))
}
