package transport

import (
	"sync"

	"buf.build/go/protovalidate"
	"github.com/Mikadore/mygosh/lib/transport/wirepb"
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

func (t *Transport) Send(envelope *wirepb.Envelope) error {
	if envelope == nil {
		return eris.New("wire: nil envelope")
	}
	if err := protovalidate.Validate(envelope); err != nil {
		return eris.Wrap(err, "validate message envelope")
	}

	packet, err := proto.Marshal(envelope)
	if err != nil {
		return eris.Wrap(err, "encode message envelope")
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if err := t.packets.Send(packet); err != nil {
		return eris.Wrapf(err, "send message envelope (%d bytes)", len(packet))
	}
	return nil
}

func (t *Transport) Receive() (*wirepb.Envelope, error) {
	packet, err := t.packets.Receive()
	if err != nil {
		return nil, err
	}
	if len(packet) == 0 {
		return nil, eris.New("wire: empty message")
	}

	var envelope wirepb.Envelope
	if err := proto.Unmarshal(packet, &envelope); err != nil {
		return nil, eris.Wrap(err, "decode message envelope")
	}
	if err := protovalidate.Validate(&envelope); err != nil {
		return nil, eris.Wrap(err, "validate message envelope")
	}
	return &envelope, nil
}
