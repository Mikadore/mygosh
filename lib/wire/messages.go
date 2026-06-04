package wire

import (
	"io"

	"github.com/rotisserie/eris"
)

type MsgType byte

const (
	MsgOpen       MsgType = 1
	MsgOpenOk     MsgType = 2
	MsgData       MsgType = 3
	MsgErr        MsgType = 4
	MsgResize     MsgType = 5
	MsgClose      MsgType = 6
	MsgExitStatus MsgType = 7
)

var msgTypeStrings = map[MsgType]string{
	MsgOpen:       "MsgOpen",
	MsgOpenOk:     "MsgOpenOk",
	MsgData:       "MsgData",
	MsgErr:        "MsgErr",
	MsgResize:     "MsgResize",
	MsgClose:      "MsgClose",
	MsgExitStatus: "MsgExitStatus",
}

func MsgTypeName(t MsgType) string {
	return msgTypeStrings[t]
}

type Message struct {
	Type    MsgType
	Payload []byte
}

type MsgStream struct {
	framed *Framed
}

func NewMsgStream(rw io.ReadWriter) *MsgStream {
	return &MsgStream{framed: NewFramed(rw)}
}

func (s *MsgStream) Send(msgType MsgType, payload []byte) error {
	msg := make([]byte, 0, 1+len(payload))
	msg = append(msg, byte(msgType))
	msg = append(msg, payload...)

	if err := s.framed.Send(msg); err != nil {
		return eris.Wrapf(err, "send message %v (%d bytes)", MsgTypeName(msgType), len(payload))
	}
	return nil
}

func (s *MsgStream) Receive() (Message, error) {
	msg, err := s.framed.Receive()
	if err != nil {
		return Message{}, err
	}
	if len(msg) == 0 {
		return Message{}, eris.New("wire: empty message")
	}

	return Message{
		Type:    MsgType(msg[0]),
		Payload: msg[1:],
	}, nil
}
