package transport

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/rotisserie/eris"
)

const MaxPayloadSize = 1 << 16

type PacketStream interface {
	Send(packet []byte) error
	Receive() ([]byte, error)
}

type Framed struct {
	rw         io.ReadWriter
	maxPayload uint32
	writeMu    sync.Mutex
}

func NewFramed(rw io.ReadWriter) *Framed {
	return &Framed{
		rw:         rw,
		maxPayload: MaxPayloadSize,
	}
}

func (t *Framed) Send(payload []byte) error {
	if len(payload) > int(t.maxPayload) {
		return eris.Errorf("wire: payload too large: %d bytes", len(payload))
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))

	frame := make([]byte, 0, len(header)+len(payload))
	frame = append(frame, header[:]...)
	frame = append(frame, payload...)

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	_, err := t.rw.Write(frame)
	return eris.Wrapf(err, "send frame (%d bytes)", len(payload))
}

func (t *Framed) Receive() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(t.rw, header[:]); err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint32(header[:])
	if size > t.maxPayload {
		return nil, eris.Errorf("wire: payload too large: %d bytes", size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(t.rw, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
