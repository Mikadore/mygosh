package wire

import (
	"errors"
	"testing"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestProtoRoundTrip(t *testing.T) {
	framer := &memoryFramer{}
	expected := &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelData{
			ChannelData: &sessionpb.ChannelData{
				RecipientChannelId: 7,
				Data:               []byte{0x00, 0x01, 'h', 'i', 0xff},
			},
		},
	}

	require.NoError(t, SendProto(framer, expected))

	var got sessionpb.Envelope
	require.NoError(t, ReceiveProto(framer, &got))
	require.True(t, proto.Equal(expected, &got))
}

func TestSendProtoRejectsInvalidInput(t *testing.T) {
	require.ErrorContains(t, SendProto(nil, &sessionpb.Envelope{}), "nil framer")
	require.ErrorContains(t, SendProto(&memoryFramer{}, nil), "nil message")
	require.ErrorContains(t, SendProto(&memoryFramer{}, &sessionpb.Envelope{}), "validate message")
}

func TestReceiveProtoRejectsInvalidInput(t *testing.T) {
	var got sessionpb.Envelope

	require.ErrorContains(t, ReceiveProto(nil, &got), "nil framer")
	require.ErrorContains(t, ReceiveProto(&memoryFramer{}, nil), "nil message")
	require.ErrorContains(t, ReceiveProto(&memoryFramer{frame: []byte{}}, &got), "empty message")
	require.ErrorContains(t, ReceiveProto(&memoryFramer{frame: []byte{0xff}}, &got), "decode message")

	unknownOnly := []byte{0x78, 0x01}
	require.ErrorContains(t, ReceiveProto(&memoryFramer{frame: unknownOnly}, &got), "validate message")
}

func TestProtoPropagatesFramerErrors(t *testing.T) {
	sendErr := errors.New("send failed")
	receiveErr := errors.New("receive failed")
	valid := &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelEof{
			ChannelEof: &sessionpb.ChannelEof{RecipientChannelId: 1},
		},
	}

	err := SendProto(&memoryFramer{sendErr: sendErr}, valid)
	require.ErrorIs(t, err, sendErr)

	var got sessionpb.Envelope
	err = ReceiveProto(&memoryFramer{receiveErr: receiveErr}, &got)
	require.ErrorIs(t, err, receiveErr)
}

type memoryFramer struct {
	frame      []byte
	sendErr    error
	receiveErr error
}

func (f *memoryFramer) SendFrame(frame []byte) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.frame = append([]byte(nil), frame...)
	return nil
}

func (f *memoryFramer) ReceiveFrame() ([]byte, error) {
	if f.receiveErr != nil {
		return nil, f.receiveErr
	}
	return append([]byte(nil), f.frame...), nil
}
