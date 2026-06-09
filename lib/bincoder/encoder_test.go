package bincoder

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncoderDecoderRoundTrip(t *testing.T) {
	terminalBytes := []byte{0x00, 0x1b, '[', '3', '1', 'm', 0xff, '\r', '\n'}

	e := NewEncoder()
	e.U32(42)
	e.Bytes(terminalBytes)
	e.UTF8String("hello")
	require.NoError(t, e.Err())

	d := NewCursor(e.Result())
	require.Equal(t, uint32(42), d.U32())
	require.Equal(t, terminalBytes, d.Bytes())
	require.Equal(t, "hello", d.UTF8String())
	require.NoError(t, d.Done())
}

func TestEncoderBytesMatchesWriteBytes(t *testing.T) {
	e := NewEncoder()
	e.Bytes([]byte("abc"))
	require.NoError(t, e.Err())

	require.Equal(t, []byte{0, 0, 0, 3, 'a', 'b', 'c'}, e.Result())
}
