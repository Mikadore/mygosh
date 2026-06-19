package service

import (
	"buf.build/go/protovalidate"
	"github.com/rotisserie/eris"
	"google.golang.org/protobuf/proto"
)

func MarshalPayload(message proto.Message) ([]byte, error) {
	if message == nil {
		return nil, eris.New("service payload message is required")
	}
	if err := protovalidate.Validate(message); err != nil {
		return nil, eris.Wrap(err, "validate service payload")
	}

	payload, err := proto.Marshal(message)
	if err != nil {
		return nil, eris.Wrap(err, "encode service payload")
	}
	return payload, nil
}

func UnmarshalPayload(payload []byte, message proto.Message) error {
	if message == nil {
		return eris.New("service payload message is required")
	}

	proto.Reset(message)
	if err := proto.Unmarshal(payload, message); err != nil {
		return eris.Wrap(err, "decode service payload")
	}
	if err := protovalidate.Validate(message); err != nil {
		return eris.Wrap(err, "validate service payload")
	}
	return nil
}
