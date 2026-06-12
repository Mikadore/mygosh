package transport

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func makeNoisePair(t *testing.T) (*NoiseStream, *NoiseStream) {
	t.Helper()

	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})

	deadline := time.Now().Add(2 * time.Second)
	require.NoError(t, a.SetDeadline(deadline))
	require.NoError(t, b.SetDeadline(deadline))

	var initiator *NoiseStream
	var responder *NoiseStream
	var err error

	errs := make(chan error, 2)
	go func() {
		initiator, err = HandshakeClient(a)
		errs <- err
	}()
	go func() {
		responder, err = HandshakeServer(b)
		errs <- err
	}()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	require.NotNil(t, initiator)
	require.NotNil(t, responder)
	require.NotEmpty(t, initiator.ChannelBinding())
	require.Equal(t, initiator.ChannelBinding(), responder.ChannelBinding())

	return initiator, responder
}

func TestDoHandshakeRoundTrip(t *testing.T) {
	makeNoisePair(t)
}

func TestNoiseStreamRoundTripInitiatorToResponder(t *testing.T) {
	initiator, responder := makeNoisePair(t)
	expected := []byte("Hello there! ...General Kenobi :3")

	requireNoiseRoundTrip(t, initiator, responder, expected)
}

func TestNoiseStreamRoundTripResponderToInitiator(t *testing.T) {
	initiator, responder := makeNoisePair(t)
	expected := []byte("You are a bold one.")

	requireNoiseRoundTrip(t, responder, initiator, expected)
}

func TestNoiseStreamTCPRoundTripExportsChannelBinding(t *testing.T) {
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

	require.NotEmpty(t, clientStream.ChannelBinding())
	require.Equal(t, clientStream.ChannelBinding(), serverStream.ChannelBinding())

	requireNoiseRoundTrip(t, clientStream, serverStream, []byte("ping over tcp"))
	requireNoiseRoundTrip(t, serverStream, clientStream, []byte("pong over tcp"))
}

func requireNoiseRoundTrip(t *testing.T, sender *NoiseStream, receiver *NoiseStream, expected []byte) {
	t.Helper()

	actualCh := make(chan []byte, 1)
	errs := make(chan error, 2)

	go func() {
		actual, err := receiver.Receive()
		if err != nil {
			errs <- err
			return
		}
		actualCh <- actual
		errs <- nil
	}()
	go func() {
		errs <- sender.Send(expected)
	}()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	actual := <-actualCh
	require.Equal(t, expected, actual)
}
