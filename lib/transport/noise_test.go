package transport

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func makeTransportPair(t *testing.T) (*Transport, *Transport) {
	t.Helper()

	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})

	deadline := time.Now().Add(2 * time.Second)
	require.NoError(t, a.SetDeadline(deadline))
	require.NoError(t, b.SetDeadline(deadline))

	type handshakeResult struct {
		transport *Transport
		err       error
	}

	initiatorResult := make(chan handshakeResult, 1)
	responderResult := make(chan handshakeResult, 1)
	go func() {
		initiator, err := HandshakeClient(a)
		initiatorResult <- handshakeResult{transport: initiator, err: err}
	}()
	go func() {
		responder, err := HandshakeServer(b)
		responderResult <- handshakeResult{transport: responder, err: err}
	}()

	initiatorHandshake := <-initiatorResult
	responderHandshake := <-responderResult
	require.NoError(t, initiatorHandshake.err)
	require.NoError(t, responderHandshake.err)

	initiator := initiatorHandshake.transport
	responder := responderHandshake.transport
	require.NotNil(t, initiator)
	require.NotNil(t, responder)
	require.NotEmpty(t, initiator.ChannelBinding())
	require.Equal(t, initiator.ChannelBinding(), responder.ChannelBinding())

	return initiator, responder
}

func TestDoHandshakeRoundTrip(t *testing.T) {
	makeTransportPair(t)
}

func TestTransportRoundTripInitiatorToResponder(t *testing.T) {
	initiator, responder := makeTransportPair(t)
	expected := []byte("Hello there! ...General Kenobi :3")

	requireTransportRoundTrip(t, initiator, responder, expected)
}

func TestTransportRoundTripResponderToInitiator(t *testing.T) {
	initiator, responder := makeTransportPair(t)
	expected := []byte("You are a bold one.")

	requireTransportRoundTrip(t, responder, initiator, expected)
}

func TestTransportTCPRoundTripExportsChannelBinding(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})

	serverStreamCh := make(chan *Transport, 1)
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

	require.NotEmpty(t, clientStream.ChannelBinding())
	require.Equal(t, clientStream.ChannelBinding(), serverStream.ChannelBinding())

	requireTransportRoundTrip(t, clientStream, serverStream, []byte("ping over tcp"))
	requireTransportRoundTrip(t, serverStream, clientStream, []byte("pong over tcp"))
}

func requireTransportRoundTrip(t *testing.T, sender *Transport, receiver *Transport, expected []byte) {
	t.Helper()

	actualCh := make(chan []byte, 1)
	errs := make(chan error, 2)

	go func() {
		actual, err := receiver.ReceiveFrame()
		if err != nil {
			errs <- err
			return
		}
		actualCh <- actual
		errs <- nil
	}()
	go func() {
		errs <- sender.SendFrame(expected)
	}()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	actual := <-actualCh
	require.Equal(t, expected, actual)
}
