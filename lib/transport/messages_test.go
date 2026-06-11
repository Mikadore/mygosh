package transport

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/wire/wirepb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type packetBuffer struct {
	buf bytes.Buffer
}

func (p *packetBuffer) Send(packet []byte) error {
	return bincoder.WriteBytes(&p.buf, packet)
}

func (p *packetBuffer) Receive() ([]byte, error) {
	return bincoder.ReadBytes(&p.buf, 0)
}

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
			stream := &packetBuffer{}
			transport := NewTransport(stream)

			require.NoError(t, transport.Send(tt.envelope))

			got, err := transport.Receive()
			require.NoError(t, err)
			require.True(t, proto.Equal(tt.envelope, got), "expected %v, got %v", tt.envelope, got)
		})
	}
}

func TestTransportRejectsNilEnvelope(t *testing.T) {
	transport := NewTransport(&packetBuffer{})
	require.Error(t, transport.Send(nil))
}

func TestDataPayloadIsUnchanged(t *testing.T) {
	transport := NewTransport(&packetBuffer{})
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
	stream := &packetBuffer{}
	require.NoError(t, stream.Send(nil))

	_, err := NewTransport(stream).Receive()
	require.Error(t, err)
}

func TestTransportRejectsEnvelopeWithoutKind(t *testing.T) {
	stream := &packetBuffer{}
	packet, err := proto.Marshal(&wirepb.Envelope{})
	require.NoError(t, err)
	require.NoError(t, stream.Send(packet))

	_, err = NewTransport(stream).Receive()
	require.Error(t, err)
}

func TestTransportRejectsInvalidResize(t *testing.T) {
	stream := &packetBuffer{}
	packet, err := proto.Marshal(&wirepb.Envelope{
		Kind: &wirepb.Envelope_Resize{
			Resize: &wirepb.Resize{
				Rows: 0,
				Cols: 80,
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, stream.Send(packet))

	_, err = NewTransport(stream).Receive()
	require.Error(t, err)
}

func TestTransportRejectsInvalidError(t *testing.T) {
	transport := NewTransport(&packetBuffer{})

	err := transport.Send(&wirepb.Envelope{
		Kind: &wirepb.Envelope_Err{
			Err: &wirepb.Error{Code: "missing-message"},
		},
	})
	require.Error(t, err)
}

func TestTransportRoundTripOverNoiseStreamTCP(t *testing.T) {
	serverStatic, err := keys.GenerateX25519()
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	serverStreamCh := make(chan *NoiseStream, 1)
	errs := make(chan error, 2)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errs <- err
			return
		}
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			_ = conn.Close()
			errs <- err
			return
		}

		stream, err := HandshakeServer(conn, serverStatic)
		if err == nil {
			serverStreamCh <- stream
		}
		errs <- err
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
	})
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))

	clientStream, err := HandshakeClient(conn)
	require.NoError(t, err)
	require.NoError(t, <-errs)
	serverStream := <-serverStreamCh

	clientTransport := NewTransport(clientStream)
	serverTransport := NewTransport(serverStream)

	expected := &wirepb.Envelope{
		Kind: &wirepb.Envelope_Data{
			Data: &wirepb.Data{Data: []byte{0x00, 0x01, 'h', 'i', 0xff}},
		},
	}

	errs = make(chan error, 2)
	gotCh := make(chan *wirepb.Envelope, 1)
	go func() {
		got, err := serverTransport.Receive()
		if err == nil {
			gotCh <- got
		}
		errs <- err
	}()
	go func() {
		errs <- clientTransport.Send(expected)
	}()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	require.True(t, proto.Equal(expected, <-gotCh))
}
