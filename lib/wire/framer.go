// Package wire defines transport-neutral framed byte streams and protobuf
// encoding over those streams.
package wire

import "io"

// Framer sends and receives complete byte frames. Implementations preserve one
// frame boundary per SendFrame call.
type Framer interface {
	SendFrame([]byte) error
	ReceiveFrame() ([]byte, error)
}

// FramedConn is a closeable framed byte stream.
type FramedConn interface {
	Framer
	io.Closer
}
