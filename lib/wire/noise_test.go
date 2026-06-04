package wire

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

	errs := make(chan error, 2)
	go func() {
		var err error
		initiator, err = Handshake(a, true)
		errs <- err
	}()
	go func() {
		var err error
		responder, err = Handshake(b, false)
		errs <- err
	}()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	require.NotNil(t, initiator)
	require.NotNil(t, responder)

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
