package wire

import (
	"bytes"
	"testing"
)

func TestMsgStreamRoundTripsMessageType(t *testing.T) {
	types := []MsgType{
		MsgOpen,
		MsgOpenOk,
		MsgData,
		MsgErr,
		MsgResize,
		MsgClose,
		MsgExitStatus,
	}

	for _, msgType := range types {
		t.Run(MsgTypeName(msgType), func(t *testing.T) {
			var buf bytes.Buffer
			stream := NewMsgStream(&buf)

			if err := stream.Send(msgType, nil); err != nil {
				t.Fatalf("send message: %v", err)
			}

			msg, err := stream.Receive()
			if err != nil {
				t.Fatalf("receive message: %v", err)
			}
			if msg.Type != msgType {
				t.Fatalf("message type = %v, want %v", msg.Type, msgType)
			}
		})
	}
}

func TestMsgDataPayloadIsUnchanged(t *testing.T) {
	var buf bytes.Buffer
	stream := NewMsgStream(&buf)
	payload := []byte{0x00, 0x01, 'h', 'i', 0xff}

	if err := stream.Send(MsgData, payload); err != nil {
		t.Fatalf("send data message: %v", err)
	}

	msg, err := stream.Receive()
	if err != nil {
		t.Fatalf("receive data message: %v", err)
	}
	if msg.Type != MsgData {
		t.Fatalf("message type = %v, want %v", msg.Type, MsgData)
	}
	if !bytes.Equal(msg.Payload, payload) {
		t.Fatalf("payload = %v, want %v", msg.Payload, payload)
	}
}

func TestMsgStreamRejectsEmptyFrame(t *testing.T) {
	var buf bytes.Buffer
	framed := NewFramed(&buf)
	if err := framed.Send(nil); err != nil {
		t.Fatalf("send empty frame: %v", err)
	}

	_, err := NewMsgStream(&buf).Receive()
	if err == nil {
		t.Fatal("receive empty message succeeded, want error")
	}
}
