package transport

import (
	"io"
	"sync"

	"buf.build/go/protovalidate"
	"github.com/rotisserie/eris"
	"google.golang.org/protobuf/proto"
)

type PacketStream interface {
	Send(packet []byte) error
	Receive() ([]byte, error)
}

type Transport struct {
	packets PacketStream
	writeMu sync.Mutex
}

func NewTransport(packets PacketStream) *Transport {
	return &Transport{packets: packets}
}

func (t *Transport) Send(message proto.Message) error {
	if message == nil {
		return eris.New("wire: nil message")
	}
	if err := protovalidate.Validate(message); err != nil {
		return eris.Wrap(err, "validate message")
	}

	packet, err := proto.Marshal(message)
	if err != nil {
		return eris.Wrap(err, "encode message")
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if err := t.packets.Send(packet); err != nil {
		return eris.Wrapf(err, "send message (%d bytes)", len(packet))
	}
	return nil
}

func (t *Transport) Receive(message proto.Message) error {
	if message == nil {
		return eris.New("wire: nil message")
	}

	packet, err := t.packets.Receive()
	if err != nil {
		return err
	}
	if len(packet) == 0 {
		return eris.New("wire: empty message")
	}

	proto.Reset(message)
	if err := proto.Unmarshal(packet, message); err != nil {
		return eris.Wrap(err, "decode message")
	}
	if err := protovalidate.Validate(message); err != nil {
		return eris.Wrap(err, "validate message")
	}
	return nil
}

func (t *Transport) Close() error {
	closer, ok := t.packets.(io.Closer)
	if !ok {
		return nil
	}
	return closer.Close()
}
