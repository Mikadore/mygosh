package transport

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/stretchr/testify/require"
)

func TestNoiseStreamSendChunkWritesBincoderFrame(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	requireFrameDeadlines(t, a, b)

	stream := &NoiseStream{conn: a}
	payload := []byte("hello")

	errs := make(chan error, 1)
	go func() {
		errs <- stream.sendChunk(payload)
	}()

	got, err := bincoder.ReadBytes(b, MaxPayloadSize)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.NoError(t, <-errs)
}

func TestNoiseStreamRecvChunkReadsSingleBincoderFrame(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	requireFrameDeadlines(t, a, b)

	stream := &NoiseStream{conn: a}
	payload := []byte("hello")
	trailing := []byte("trailing")

	encoder := bincoder.NewEncoder()
	encoder.Bytes(payload)
	require.NoError(t, encoder.Err())

	frame := append([]byte{}, encoder.Result()...)
	frame = append(frame, trailing...)

	errs := make(chan error, 1)
	go func() {
		_, err := b.Write(frame)
		errs <- err
	}()

	got, err := stream.recvChunk()
	require.NoError(t, err)
	require.Equal(t, payload, got)

	remaining := make([]byte, len(trailing))
	_, err = io.ReadFull(a, remaining)
	require.NoError(t, err)
	require.Equal(t, trailing, remaining)
	require.NoError(t, <-errs)
}

func TestNoiseStreamRoundTripEmptyPayload(t *testing.T) {
	sender, receiver := makeNoiseFramePair(t)

	actualCh := make(chan []byte, 1)
	errs := make(chan error, 2)

	go func() {
		actual, err := receiver.recvChunk()
		if err != nil {
			errs <- err
			return
		}
		actualCh <- actual
		errs <- nil
	}()
	go func() {
		errs <- sender.sendChunk(nil)
	}()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	require.Empty(t, <-actualCh)
}

func TestNoiseStreamRejectsOversizedSendChunk(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})

	stream := &NoiseStream{conn: a}

	err := stream.sendChunk(make([]byte, MaxPayloadSize+1))
	require.ErrorContains(t, err, "wire: payload too large")
}

func TestNoiseStreamRejectsOversizedRecvChunk(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	requireFrameDeadlines(t, a, b)

	stream := &NoiseStream{conn: a}

	errs := make(chan error, 1)
	go func() {
		errs <- bincoder.WriteU32(b, uint32(MaxPayloadSize+1))
	}()

	_, err := stream.recvChunk()
	require.ErrorContains(t, err, "exceeds maximum")
	require.NoError(t, <-errs)
}

func TestNoiseStreamDelegatesConnMethods(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})

	stream := &NoiseStream{conn: a}
	deadline := time.Now().Add(2 * time.Second)

	require.Equal(t, a.LocalAddr().String(), stream.LocalAddr().String())
	require.Equal(t, a.RemoteAddr().String(), stream.RemoteAddr().String())
	require.NoError(t, stream.SetDeadline(deadline))
	require.NoError(t, stream.SetReadDeadline(deadline))
	require.NoError(t, stream.SetWriteDeadline(deadline))
	require.NoError(t, stream.Close())
}

func makeNoiseFramePair(t *testing.T) (*NoiseStream, *NoiseStream) {
	t.Helper()

	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	requireFrameDeadlines(t, a, b)

	return &NoiseStream{conn: a}, &NoiseStream{conn: b}
}

func requireFrameDeadlines(t *testing.T, conns ...net.Conn) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for _, conn := range conns {
		require.NoError(t, conn.SetDeadline(deadline))
	}
}
