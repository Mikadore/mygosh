package establish

import (
	"net"
	"time"

	"github.com/rotisserie/eris"
)

const (
	defaultHandshakeTimeout = 5 * time.Second
	defaultAuthTimeout      = 10 * time.Second
)

func validateTimeouts(handshakeTimeout time.Duration, authTimeout time.Duration) error {
	if handshakeTimeout < 0 {
		return eris.New("handshake timeout must be non-negative")
	}
	if authTimeout < 0 {
		return eris.New("auth timeout must be non-negative")
	}
	return nil
}

func resolveTimeout(actual time.Duration, fallback time.Duration) time.Duration {
	if actual == 0 {
		return fallback
	}
	return actual
}

func remoteAddrString(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "unknown"
	}
	return conn.RemoteAddr().String()
}
