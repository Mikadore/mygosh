package wire

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransportRoundTripsMessageType(t *testing.T) {
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
			transport := NewTransport(NewFramed(&buf))

			require.NoError(t, transport.SendMessage(msgType, nil))

			msg, err := transport.ReceiveMessage()
			require.NoError(t, err)
			require.Equal(t, msgType, msg.Type)
		})
	}
}

func TestMsgDataPayloadIsUnchanged(t *testing.T) {
	var buf bytes.Buffer
	transport := NewTransport(NewFramed(&buf))
	payload := []byte{0x00, 0x01, 'h', 'i', 0xff}

	require.NoError(t, transport.SendData(payload))

	msg, err := transport.ReceiveMessage()
	require.NoError(t, err)
	require.Equal(t, MsgData, msg.Type)
	require.Equal(t, payload, msg.Payload)
}

func TestTransportRejectsEmptyPacket(t *testing.T) {
	var buf bytes.Buffer
	framed := NewFramed(&buf)
	require.NoError(t, framed.Send(nil))

	_, err := NewTransport(NewFramed(&buf)).ReceiveMessage()
	require.Error(t, err)
}

func TestTransportRoundTripsOpenEvent(t *testing.T) {
	var buf bytes.Buffer
	transport := NewTransport(NewFramed(&buf))
	req := OpenRequest{
		Term: "xterm-256color",
		Rows: 24,
		Cols: 80,
	}

	require.NoError(t, transport.SendOpen(req))

	event, err := transport.ReceiveEvent()
	require.NoError(t, err)
	require.Equal(t, OpenEvent{Request: req}, event)
}

func TestTransportRoundTripsResizeEvent(t *testing.T) {
	var buf bytes.Buffer
	transport := NewTransport(NewFramed(&buf))
	resize := Resize{Rows: 40, Cols: 120}

	require.NoError(t, transport.SendResize(resize))

	event, err := transport.ReceiveEvent()
	require.NoError(t, err)
	require.Equal(t, ResizeEvent{Resize: resize}, event)
}

func TestTransportReceivesDataEventWithoutTransformingPayload(t *testing.T) {
	var buf bytes.Buffer
	transport := NewTransport(NewFramed(&buf))
	payload := []byte{0x00, 0x01, 'h', 'i', 0xff}

	require.NoError(t, transport.SendData(payload))

	event, err := transport.ReceiveEvent()
	require.NoError(t, err)
	require.Equal(t, DataEvent{Bytes: payload}, event)
}

func TestTransportRejectsUnknownMessageTypeEvent(t *testing.T) {
	var buf bytes.Buffer
	transport := NewTransport(NewFramed(&buf))

	require.NoError(t, transport.SendMessage(MsgType(99), nil))

	_, err := transport.ReceiveEvent()
	require.Error(t, err)
}
