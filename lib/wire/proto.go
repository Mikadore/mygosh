package wire

import (
	"buf.build/go/protovalidate"
	"github.com/rotisserie/eris"
	"google.golang.org/protobuf/proto"
)

func SendProto(framer Framer, message proto.Message) error {
	if framer == nil {
		return eris.New("wire: nil framer")
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

	if err := framer.SendFrame(packet); err != nil {
		return eris.Wrapf(err, "send message (%d bytes)", len(packet))
	}
	return nil
}

func ReceiveProto(framer Framer, message proto.Message) error {
	if framer == nil {
		return eris.New("wire: nil framer")
	}
	if message == nil {
		return eris.New("wire: nil message")
	}

	packet, err := framer.ReceiveFrame()
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
