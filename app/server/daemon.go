package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mikadore/mygosh/app/config"
	"github.com/rotisserie/eris"
)

type connectionHandler func(context.Context, net.Conn, string) error

type connectionAdmission struct {
	mu       sync.Mutex
	maxTotal int
	maxPerIP int
	total    int
	perIP    map[string]int
}

func newConnectionAdmission(maxTotal, maxPerIP int) *connectionAdmission {
	return &connectionAdmission{
		maxTotal: maxTotal,
		maxPerIP: maxPerIP,
		perIP:    make(map[string]int),
	}
}

func (a *connectionAdmission) acquire(source string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total >= a.maxTotal || a.perIP[source] >= a.maxPerIP {
		return false
	}
	a.total++
	a.perIP[source]++
	return true
}

func (a *connectionAdmission) release(source string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total > 0 {
		a.total--
	}
	if a.perIP[source] <= 1 {
		delete(a.perIP, source)
		return
	}
	a.perIP[source]--
}

func (a *connectionAdmission) snapshot(source string) (total int, sourceTotal int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.total, a.perIP[source]
}

func runDaemon(
	ctx context.Context,
	listener net.Listener,
	cfg config.ServerDaemon,
	logger *slog.Logger,
	handle connectionHandler,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if listener == nil {
		return eris.New("server listener is required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if handle == nil {
		return eris.New("connection handler is required")
	}

	admission := newConnectionAdmission(cfg.MaxConnections, cfg.MaxConnectionsPerIP)
	var connections sync.WaitGroup
	var nextConnectionID atomic.Uint64

	stopClosingListener := context.AfterFunc(ctx, func() {
		_ = listener.Close()
	})
	defer stopClosingListener()
	defer listener.Close() //nolint:errcheck

	var temporaryDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() {
				if temporaryDelay == 0 {
					temporaryDelay = 5 * time.Millisecond
				} else {
					temporaryDelay *= 2
				}
				if temporaryDelay > time.Second {
					temporaryDelay = time.Second
				}
				logger.Warn("temporary accept failure", "err", err, "retry_in", temporaryDelay)
				timer := time.NewTimer(temporaryDelay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					if !timer.Stop() {
						<-timer.C
					}
				}
				continue
			}
			return eris.Wrap(err, "accept connection")
		}
		temporaryDelay = 0

		source := normalizedSourceIP(conn.RemoteAddr())
		if !admission.acquire(source) {
			active, activeSource := admission.snapshot(source)
			logger.Warn(
				"connection rejected by admission limits",
				"remote", conn.RemoteAddr(),
				"source_ip", source,
				"active_connections", active,
				"active_source_connections", activeSource,
			)
			_ = conn.Close()
			continue
		}

		connectionID := fmt.Sprintf("%016x", nextConnectionID.Add(1))
		active, activeSource := admission.snapshot(source)
		logger.Info(
			"accepted connection",
			"connection_id", connectionID,
			"remote", conn.RemoteAddr(),
			"source_ip", source,
			"active_connections", active,
			"active_source_connections", activeSource,
		)
		connections.Add(1)
		go func() {
			startedAt := time.Now()
			defer connections.Done()
			defer conn.Close() //nolint:errcheck
			defer func() {
				admission.release(source)
				active, activeSource := admission.snapshot(source)
				logger.Debug(
					"connection closed",
					"connection_id", connectionID,
					"remote", conn.RemoteAddr(),
					"duration", time.Since(startedAt),
					"active_connections", active,
					"active_source_connections", activeSource,
				)
			}()
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error(
						"connection handler panicked",
						"connection_id", connectionID,
						"remote", conn.RemoteAddr(),
						"panic", recovered,
					)
				}
			}()

			if err := handle(ctx, conn, connectionID); err != nil &&
				!errors.Is(err, context.Canceled) &&
				!errors.Is(err, net.ErrClosed) {
				logger.Error(
					"connection ended with error",
					"connection_id", connectionID,
					"remote", conn.RemoteAddr(),
					"err", err,
				)
			} else {
				logger.Debug(
					"connection handler completed",
					"connection_id", connectionID,
					"remote", conn.RemoteAddr(),
				)
			}
		}()
	}

	active, _ := admission.snapshot("")
	logger.Info(
		"server shutdown requested",
		"cause", context.Cause(ctx),
		"active_connections", active,
		"shutdown_timeout", cfg.ShutdownTimeout,
	)
	done := make(chan struct{})
	go func() {
		connections.Wait()
		close(done)
	}()

	timer := time.NewTimer(cfg.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
		logger.Info("server shutdown complete")
		return nil
	case <-timer.C:
		active, _ := admission.snapshot("")
		logger.Error(
			"server shutdown timed out",
			"active_connections", active,
			"shutdown_timeout", cfg.ShutdownTimeout,
		)
		return eris.Errorf("server shutdown exceeded %s", cfg.ShutdownTimeout)
	}
}

func normalizedSourceIP(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	return ip.Unmap().String()
}
