package transport

import (
	"bytes"
	"testing"

	"github.com/Mikadore/mygosh/lib/transport/wirepb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestTransportRoundTripsEnvelopeKinds(t *testing.T) {
	tests := []struct {
		name     string
		envelope *wirepb.Envelope
	}{
		{
			name: "open",
			envelope: &wirepb.Envelope{
				Kind: &wirepb.Envelope_Open{
					Open: &wirepb.OpenRequest{
						Term: "xterm-256color",
						Rows: 24,
						Cols: 80,
					},
				},
			},
		},
		{
			name: "open ok",
			envelope: &wirepb.Envelope{
				Kind: &wirepb.Envelope_OpenOk{
					OpenOk: &wirepb.OpenResponse{SessionId: "session-1"},
				},
			},
		},
		{
			name: "data",
			envelope: &wirepb.Envelope{
				Kind: &wirepb.Envelope_Data{
					Data: &wirepb.Data{Data: []byte{0x00, 0x01, 'h', 'i', 0xff}},
				},
			},
		},
		{
			name: "err",
			envelope: &wirepb.Envelope{
				Kind: &wirepb.Envelope_Err{
					Err: &wirepb.Error{Code: "failed", Message: "failed"},
				},
			},
		},
		{
			name: "resize",
			envelope: &wirepb.Envelope{
				Kind: &wirepb.Envelope_Resize{
					Resize: &wirepb.Resize{Rows: 40, Cols: 120},
				},
			},
		},
		{
			name: "close",
			envelope: &wirepb.Envelope{
				Kind: &wirepb.Envelope_Close{
					Close: &wirepb.Close{Reason: "stdin closed"},
				},
			},
		},
		{
			name: "exit status",
			envelope: &wirepb.Envelope{
				Kind: &wirepb.Envelope_ExitStatus{
					ExitStatus: &wirepb.ExitStatus{Code: 12},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			transport := NewTransport(NewFramed(&buf))

			require.NoError(t, transport.Send(tt.envelope))

			got, err := transport.Receive()
			require.NoError(t, err)
			require.True(t, proto.Equal(tt.envelope, got), "expected %v, got %v", tt.envelope, got)
		})
	}
}

func TestTransportRejectsNilEnvelope(t *testing.T) {
	var buf bytes.Buffer
	transport := NewTransport(NewFramed(&buf))

	require.Error(t, transport.Send(nil))
}

func TestDataPayloadIsUnchanged(t *testing.T) {
	var buf bytes.Buffer
	transport := NewTransport(NewFramed(&buf))
	payload := []byte{0x00, 0x01, 'h', 'i', 0xff}

	require.NoError(t, transport.Send(&wirepb.Envelope{
		Kind: &wirepb.Envelope_Data{
			Data: &wirepb.Data{Data: payload},
		},
	}))

	got, err := transport.Receive()
	require.NoError(t, err)
	require.Equal(t, payload, got.GetData().GetData())
}

func TestTransportRejectsEmptyPacket(t *testing.T) {
	var buf bytes.Buffer
	framed := NewFramed(&buf)
	require.NoError(t, framed.Send(nil))

	_, err := NewTransport(NewFramed(&buf)).Receive()
	require.Error(t, err)
}

func TestTransportRejectsEnvelopeWithoutKind(t *testing.T) {
	var buf bytes.Buffer
	framed := NewFramed(&buf)
	packet, err := proto.Marshal(&wirepb.Envelope{})
	require.NoError(t, err)
	require.NoError(t, framed.Send(packet))

	_, err = NewTransport(NewFramed(&buf)).Receive()
	require.Error(t, err)
}

func TestTransportRejectsInvalidResize(t *testing.T) {
	var buf bytes.Buffer
	framed := NewFramed(&buf)
	packet, err := proto.Marshal(&wirepb.Envelope{
		Kind: &wirepb.Envelope_Resize{
			Resize: &wirepb.Resize{
				Rows: 0,
				Cols: 80,
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, framed.Send(packet))

	_, err = NewTransport(NewFramed(&buf)).Receive()
	require.Error(t, err)
}

func TestTransportRejectsInvalidError(t *testing.T) {
	var buf bytes.Buffer
	transport := NewTransport(NewFramed(&buf))

	err := transport.Send(&wirepb.Envelope{
		Kind: &wirepb.Envelope_Err{
			Err: &wirepb.Error{Code: "missing-message"},
		},
	})
	require.Error(t, err)
}
