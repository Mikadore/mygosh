package wire

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/rotisserie/eris"
)

const MaxPayloadSize = 1 << 20

type FrameType byte

const (
	FrameData FrameType = 'D'
	FrameErr  FrameType = 'E'
)

type Conn struct {
	r          io.Reader
	w          io.Writer
	maxPayload uint32
	writeMu    sync.Mutex
}

type Frame struct {
	Type    FrameType
	Payload []byte
}

func NewConn(rw io.ReadWriter) *Conn {
	return New(rw, rw)
}

func New(r io.Reader, w io.Writer) *Conn {
	return &Conn{
		r:          r,
		w:          w,
		maxPayload: MaxPayloadSize,
	}
}

func (c *Conn) Send(frameType FrameType, payload []byte) error {
	if len(payload) > int(c.maxPayload) {
		return eris.Errorf("wire: payload too large: %d bytes", len(payload))
	}

	var header [5]byte
	header[0] = byte(frameType)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := writeFull(c.w, header[:]); err != nil {
		return err
	}
	return writeFull(c.w, payload)
}

func (c *Conn) Receive() (Frame, error) {
	var header [5]byte
	if _, err := io.ReadFull(c.r, header[:]); err != nil {
		return Frame{}, err
	}

	size := binary.BigEndian.Uint32(header[1:])
	if size > c.maxPayload {
		return Frame{}, eris.Errorf("wire: payload too large: %d bytes", size)
	}

	frame := Frame{
		Type:    FrameType(header[0]),
		Payload: make([]byte, size),
	}
	if _, err := io.ReadFull(c.r, frame.Payload); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
