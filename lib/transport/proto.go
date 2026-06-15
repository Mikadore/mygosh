package transport

import (
	"buf.build/go/protovalidate"
	"github.com/rotisserie/eris"
	"google.golang.org/protobuf/proto"
)

func SendProto(t Framer, message proto.Message) error {
	if t == nil {
		return eris.New("wire: nil transport")
	}
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

	if err := t.SendFrame(packet); err != nil {
		return eris.Wrapf(err, "send message (%d bytes)", len(packet))
	}
	return nil
}

func ReceiveProto(t Framer, message proto.Message) error {
	if t == nil {
		return eris.New("wire: nil transport")
	}
	if message == nil {
		return eris.New("wire: nil message")
	}

	packet, err := t.ReceiveFrame()
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
