package session

import (
	"net"
	"time"

	"github.com/rotisserie/eris"
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

func remoteAddrString(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "unknown"
	}
	return conn.RemoteAddr().String()
}
