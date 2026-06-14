package transport

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/Mikadore/mygosh/lib/session/sessionpb"
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

func TestTransportRoundTripsSessionEnvelopes(t *testing.T) {
	tests := []struct {
		name    string
		message *sessionpb.Envelope
	}{
		{
			name: "open",
			message: &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Open{
					Open: &sessionpb.OpenRequest{
						Term: "xterm-256color",
						Rows: 24,
						Cols: 80,
					},
				},
			},
		},
		{
			name: "open ok",
			message: &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_OpenOk{
					OpenOk: &sessionpb.OpenResponse{SessionId: "session-1"},
				},
			},
		},
		{
			name: "data",
			message: &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Data{
					Data: &sessionpb.Data{Data: []byte{0x00, 0x01, 'h', 'i', 0xff}},
				},
			},
		},
		{
			name: "err",
			message: &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Err{
					Err: &sessionpb.Error{Code: "failed", Message: "failed"},
				},
			},
		},
		{
			name: "resize",
			message: &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Resize{
					Resize: &sessionpb.Resize{Rows: 40, Cols: 120},
				},
			},
		},
		{
			name: "close",
			message: &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Close{
					Close: &sessionpb.Close{Reason: "stdin closed"},
				},
			},
		},
		{
			name: "exit status",
			message: &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_ExitStatus{
					ExitStatus: &sessionpb.ExitStatus{Code: 12},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := &packetBuffer{}
			transport := NewTransport(stream)

			require.NoError(t, transport.Send(tt.message))

			var got sessionpb.Envelope
			require.NoError(t, transport.Receive(&got))
			require.True(t, proto.Equal(tt.message, &got), "expected %v, got %v", tt.message, &got)
		})
	}
}

func TestTransportRoundTripsAuthFrames(t *testing.T) {
	tests := []struct {
		name    string
		message *authpb.AuthFrame
	}{
		{
			name: "host auth init",
			message: &authpb.AuthFrame{
				Kind: &authpb.AuthFrame_HostAuthInit{
					HostAuthInit: &authpb.HostAuthInit{
						MygoshAuthVersion: "mygosh-auth-v1",
						ClientNonce:       bytes.Repeat([]byte{0x11}, 32),
						ReferenceIdentity: "server.example.test",
					},
				},
			},
		},
		{
			name: "server auth",
			message: &authpb.AuthFrame{
				Kind: &authpb.AuthFrame_ServerAuth{
					ServerAuth: &authpb.ServerAuth{
						ServerHostKey: []byte("server-host-key"),
						ServerNonce:   bytes.Repeat([]byte{0x22}, 32),
						Signature:     []byte("server-signature"),
					},
				},
			},
		},
		{
			name: "client auth request",
			message: &authpb.AuthFrame{
				Kind: &authpb.AuthFrame_ClientAuthRequest{
					ClientAuthRequest: &authpb.ClientAuthRequest{
						Username:              "alice",
						ClientPublicKeyOrCert: []byte("client-key"),
						ClientSigAlg:          "ed25519",
						Signature:             []byte("client-signature"),
					},
				},
			},
		},
		{
			name: "client auth ok",
			message: &authpb.AuthFrame{
				Kind: &authpb.AuthFrame_ClientAuthResponse{
					ClientAuthResponse: &authpb.ClientAuthResponse{
						Result: &authpb.ClientAuthResponse_Ok{
							Ok: &authpb.AuthSuccess{},
						},
					},
				},
			},
		},
		{
			name: "client auth reject",
			message: &authpb.AuthFrame{
				Kind: &authpb.AuthFrame_ClientAuthResponse{
					ClientAuthResponse: &authpb.ClientAuthResponse{
						Result: &authpb.ClientAuthResponse_Reject{
							Reject: &authpb.AuthReject{
								Code:    "unauthorized-client",
								Message: "not authorized",
							},
						},
					},
				},
			},
		},
		{
			name: "auth error",
			message: &authpb.AuthFrame{
				Kind: &authpb.AuthFrame_Error{
					Error: &authpb.AuthError{
						Code:    "protocol-error",
						Message: "unexpected frame",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := &packetBuffer{}
			transport := NewTransport(stream)

			require.NoError(t, transport.Send(tt.message))

			var got authpb.AuthFrame
			require.NoError(t, transport.Receive(&got))
			require.True(t, proto.Equal(tt.message, &got), "expected %v, got %v", tt.message, &got)
		})
	}
}

func TestTransportRejectsNilMessage(t *testing.T) {
	transport := NewTransport(&packetBuffer{})
	require.Error(t, transport.Send(nil))
}

func TestDataPayloadIsUnchanged(t *testing.T) {
	transport := NewTransport(&packetBuffer{})
	payload := []byte{0x00, 0x01, 'h', 'i', 0xff}

	require.NoError(t, transport.Send(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_Data{
			Data: &sessionpb.Data{Data: payload},
		},
	}))

	var got sessionpb.Envelope
	require.NoError(t, transport.Receive(&got))
	require.Equal(t, payload, got.GetData().GetData())
}

func TestTransportRejectsEmptyPacket(t *testing.T) {
	stream := &packetBuffer{}
	require.NoError(t, stream.Send(nil))

	var got sessionpb.Envelope
	err := NewTransport(stream).Receive(&got)
	require.Error(t, err)
}

func TestTransportRejectsEnvelopeWithoutKind(t *testing.T) {
	stream := &packetBuffer{}
	packet, err := proto.Marshal(&sessionpb.Envelope{})
	require.NoError(t, err)
	require.NoError(t, stream.Send(packet))

	var got sessionpb.Envelope
	err = NewTransport(stream).Receive(&got)
	require.Error(t, err)
}

func TestTransportRejectsInvalidResize(t *testing.T) {
	stream := &packetBuffer{}
	packet, err := proto.Marshal(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_Resize{
			Resize: &sessionpb.Resize{
				Rows: 0,
				Cols: 80,
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, stream.Send(packet))

	var got sessionpb.Envelope
	err = NewTransport(stream).Receive(&got)
	require.Error(t, err)
}

func TestTransportRejectsInvalidAuthFrame(t *testing.T) {
	transport := NewTransport(&packetBuffer{})

	err := transport.Send(&authpb.AuthFrame{
		Kind: &authpb.AuthFrame_HostAuthInit{
			HostAuthInit: &authpb.HostAuthInit{
				MygoshAuthVersion: "mygosh-auth-v1",
				ClientNonce:       []byte("short"),
				ReferenceIdentity: "server.example.test",
			},
		},
	})
	require.Error(t, err)
}

func TestTransportRoundTripOverNoiseStreamTCP(t *testing.T) {
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

		stream, err := HandshakeServer(conn)
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

	expected := &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_Error{
			Error: &authpb.AuthError{
				Code:    "test",
				Message: "message",
			},
		},
	}

	errs = make(chan error, 2)
	gotCh := make(chan *authpb.AuthFrame, 1)
	go func() {
		var got authpb.AuthFrame
		err := serverTransport.Receive(&got)
		if err == nil {
			gotCh <- &got
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
