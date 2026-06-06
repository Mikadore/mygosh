package wire

import (
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
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
	if name, ok := msgTypeStrings[t]; ok {
		return name
	}
	return fmt.Sprintf("MsgType(%d)", t)
}

type Message struct {
	Type    MsgType
	Payload []byte
}

type OpenRequest struct {
	Term string `cbor:"term,omitempty"`
	Rows uint16 `cbor:"rows,omitempty"`
	Cols uint16 `cbor:"cols,omitempty"`
}

type OpenResponse struct {
	SessionID string `cbor:"session_id,omitempty"`
}

type Resize struct {
	Rows uint16 `cbor:"rows"`
	Cols uint16 `cbor:"cols"`
}

type Close struct {
	Reason string `cbor:"reason,omitempty"`
}

type ExitStatus struct {
	Code int `cbor:"code"`
}

type ErrorPayload struct {
	Code    string `cbor:"code,omitempty"`
	Message string `cbor:"message"`
}

type Event interface {
	msgEvent()
}

type OpenEvent struct {
	Request OpenRequest
}

func (OpenEvent) msgEvent() {}

type OpenOKEvent struct {
	Response OpenResponse
}

func (OpenOKEvent) msgEvent() {}

type DataEvent struct {
	Bytes []byte
}

func (DataEvent) msgEvent() {}

type ErrEvent struct {
	Error ErrorPayload
}

func (ErrEvent) msgEvent() {}

type ResizeEvent struct {
	Resize Resize
}

func (ResizeEvent) msgEvent() {}

type CloseEvent struct {
	Close Close
}

func (CloseEvent) msgEvent() {}

type ExitStatusEvent struct {
	Status ExitStatus
}

func (ExitStatusEvent) msgEvent() {}

type Transport struct {
	packets PacketStream
	writeMu sync.Mutex
}

func NewTransport(packets PacketStream) *Transport {
	return &Transport{packets: packets}
}

func (t *Transport) SendMessage(msgType MsgType, payload []byte) error {
	msg := make([]byte, 0, 1+len(payload))
	msg = append(msg, byte(msgType))
	msg = append(msg, payload...)

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if err := t.packets.Send(msg); err != nil {
		return eris.Wrapf(err, "send message %v (%d bytes)", MsgTypeName(msgType), len(payload))
	}
	return nil
}

func (t *Transport) ReceiveMessage() (Message, error) {
	msg, err := t.packets.Receive()
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

func (t *Transport) SendOpen(req OpenRequest) error {
	return t.sendCBOR(MsgOpen, req)
}

func (t *Transport) SendOpenOK(resp OpenResponse) error {
	return t.sendCBOR(MsgOpenOk, resp)
}

func (t *Transport) SendData(p []byte) error {
	return t.SendMessage(MsgData, p)
}

func (t *Transport) SendErr(err ErrorPayload) error {
	return t.sendCBOR(MsgErr, err)
}

func (t *Transport) SendResize(resize Resize) error {
	return t.sendCBOR(MsgResize, resize)
}

func (t *Transport) SendClose(close Close) error {
	if close == (Close{}) {
		return t.SendMessage(MsgClose, nil)
	}
	return t.sendCBOR(MsgClose, close)
}

func (t *Transport) SendExitStatus(status ExitStatus) error {
	return t.sendCBOR(MsgExitStatus, status)
}

func (t *Transport) ReceiveEvent() (Event, error) {
	msg, err := t.ReceiveMessage()
	if err != nil {
		return nil, err
	}

	switch msg.Type {
	case MsgOpen:
		var req OpenRequest
		if err := decodeCBOR(msg.Type, msg.Payload, &req); err != nil {
			return nil, err
		}
		return OpenEvent{Request: req}, nil
	case MsgOpenOk:
		var resp OpenResponse
		if err := decodeCBOR(msg.Type, msg.Payload, &resp); err != nil {
			return nil, err
		}
		return OpenOKEvent{Response: resp}, nil
	case MsgData:
		return DataEvent{Bytes: msg.Payload}, nil
	case MsgErr:
		var wireErr ErrorPayload
		if err := decodeCBOR(msg.Type, msg.Payload, &wireErr); err != nil {
			return nil, err
		}
		return ErrEvent{Error: wireErr}, nil
	case MsgResize:
		var resize Resize
		if err := decodeCBOR(msg.Type, msg.Payload, &resize); err != nil {
			return nil, err
		}
		return ResizeEvent{Resize: resize}, nil
	case MsgClose:
		var close Close
		if len(msg.Payload) > 0 {
			if err := decodeCBOR(msg.Type, msg.Payload, &close); err != nil {
				return nil, err
			}
		}
		return CloseEvent{Close: close}, nil
	case MsgExitStatus:
		var status ExitStatus
		if err := decodeCBOR(msg.Type, msg.Payload, &status); err != nil {
			return nil, err
		}
		return ExitStatusEvent{Status: status}, nil
	default:
		return nil, eris.Errorf("wire: unknown message type %d", msg.Type)
	}
}

func (t *Transport) sendCBOR(msgType MsgType, value any) error {
	payload, err := cbor.Marshal(value)
	if err != nil {
		return eris.Wrapf(err, "encode %v payload", MsgTypeName(msgType))
	}
	return t.SendMessage(msgType, payload)
}

func decodeCBOR(msgType MsgType, payload []byte, value any) error {
	if len(payload) == 0 {
		return eris.Errorf("wire: empty %v payload", MsgTypeName(msgType))
	}
	if err := cbor.Unmarshal(payload, value); err != nil {
		return eris.Wrapf(err, "decode %v payload", MsgTypeName(msgType))
	}
	return nil
}
