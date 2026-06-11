package bincoder

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncoderDecoderRoundTrip(t *testing.T) {
	terminalBytes := []byte{0x00, 0x1b, '[', '3', '1', 'm', 0xff, '\r', '\n'}

	e := NewEncoder()
	e.Byte(0xab)
	e.Bool(true)
	e.Bool(false)
	e.U32(42)
	e.Bytes(terminalBytes)
	e.UTF8String("hello")
	require.NoError(t, e.Err())

	d := NewCursor(e.Result())
	require.Equal(t, byte(0xab), d.Byte())
	require.True(t, d.Bool())
	require.False(t, d.Bool())
	require.Equal(t, uint32(42), d.U32())
	require.Equal(t, terminalBytes, d.Bytes())
	require.Equal(t, "hello", d.UTF8String())
	require.NoError(t, d.Done())
}

func TestDecoderBoolRejectsInvalidValue(t *testing.T) {
	d := NewCursor([]byte{2})

	require.False(t, d.Bool())
	require.ErrorContains(t, d.Err(), "invalid bool byte 2 at offset 0")
}

func TestEncoderBytesMatchesWriteBytes(t *testing.T) {
	e := NewEncoder()
	e.Bytes([]byte("abc"))
	require.NoError(t, e.Err())

	require.Equal(t, []byte{0, 0, 0, 3, 'a', 'b', 'c'}, e.Result())
}

func TestEncoderByteAndBoolMatchWireFormat(t *testing.T) {
	e := NewEncoder()
	e.Byte(0xaa)
	e.Bool(true)
	e.Bool(false)
	require.NoError(t, e.Err())

	require.Equal(t, []byte{0xaa, 0x01, 0x00}, e.Result())
}
