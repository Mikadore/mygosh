package transport

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSendReceiveProtoRoundTripsSessionEnvelopes(t *testing.T) {
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
			sender, receiver := makeTransportPair(t)
			var got sessionpb.Envelope
			requireProtoRoundTrip(t, sender, receiver, tt.message, &got)
		})
	}
}

func TestSendReceiveProtoRoundTripsAuthFrames(t *testing.T) {
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
			sender, receiver := makeTransportPair(t)
			var got authpb.AuthFrame
			requireProtoRoundTrip(t, sender, receiver, tt.message, &got)
		})
	}
}

func TestSendProtoRejectsNilMessage(t *testing.T) {
	sender, _ := makeTransportPair(t)
	require.Error(t, SendProto(sender, nil))
}

func TestDataPayloadIsUnchanged(t *testing.T) {
	sender, receiver := makeTransportPair(t)
	payload := []byte{0x00, 0x01, 'h', 'i', 0xff}
	expected := &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_Data{
			Data: &sessionpb.Data{Data: payload},
		},
	}

	var got sessionpb.Envelope
	requireProtoRoundTrip(t, sender, receiver, expected, &got)
	require.Equal(t, payload, got.GetData().GetData())
}

func TestReceiveProtoRejectsEmptyFrame(t *testing.T) {
	sender, receiver := makeTransportPair(t)

	var got sessionpb.Envelope
	err := receiveProtoFromRawFrame(t, sender, receiver, nil, &got)
	require.Error(t, err)
}

func TestReceiveProtoRejectsEnvelopeWithoutKind(t *testing.T) {
	sender, receiver := makeTransportPair(t)

	packet, err := proto.Marshal(&sessionpb.Envelope{})
	require.NoError(t, err)

	var got sessionpb.Envelope
	err = receiveProtoFromRawFrame(t, sender, receiver, packet, &got)
	require.Error(t, err)
}

func TestReceiveProtoRejectsInvalidResize(t *testing.T) {
	sender, receiver := makeTransportPair(t)

	packet, err := proto.Marshal(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_Resize{
			Resize: &sessionpb.Resize{
				Rows: 0,
				Cols: 80,
			},
		},
	})
	require.NoError(t, err)

	var got sessionpb.Envelope
	err = receiveProtoFromRawFrame(t, sender, receiver, packet, &got)
	require.Error(t, err)
}

func TestSendProtoRejectsInvalidAuthFrame(t *testing.T) {
	sender, _ := makeTransportPair(t)

	err := SendProto(sender, &authpb.AuthFrame{
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

func TestSendReceiveProtoOverTCPTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	serverTransportCh := make(chan *Transport, 1)
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

		messageTransport, err := HandshakeServer(conn)
		if err == nil {
			serverTransportCh <- messageTransport
		}
		errs <- err
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
	})
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))

	clientTransport, err := HandshakeClient(conn)
	require.NoError(t, err)
	require.NoError(t, <-errs)
	serverTransport := <-serverTransportCh

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
		err := ReceiveProto(serverTransport, &got)
		if err == nil {
			gotCh <- &got
		}
		errs <- err
	}()
	go func() {
		errs <- SendProto(clientTransport, expected)
	}()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	require.True(t, proto.Equal(expected, <-gotCh))
}

func requireProtoRoundTrip(t *testing.T, sender, receiver *Transport, expected proto.Message, got proto.Message) {
	t.Helper()

	errs := make(chan error, 2)
	go func() {
		errs <- SendProto(sender, expected)
	}()
	go func() {
		errs <- ReceiveProto(receiver, got)
	}()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	require.True(t, proto.Equal(expected, got), "expected %v, got %v", expected, got)
}

func receiveProtoFromRawFrame(t *testing.T, sender, receiver *Transport, frame []byte, got proto.Message) error {
	t.Helper()

	sendErrs := make(chan error, 1)
	go func() {
		sendErrs <- sender.SendFrame(frame)
	}()

	err := ReceiveProto(receiver, got)
	require.NoError(t, <-sendErrs)
	return err
}
