package bincoder

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWriteBytesEmptyPayloadOverPipe(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})

	deadline := time.Now().Add(2 * time.Second)
	require.NoError(t, a.SetDeadline(deadline))
	require.NoError(t, b.SetDeadline(deadline))

	errs := make(chan error, 1)
	go func() {
		errs <- WriteBytes(a, nil)
	}()

	got, err := ReadBytes(b, 0)
	require.NoError(t, err)
	require.Empty(t, got)
	require.NoError(t, <-errs)
}

func TestWriteByteAndBoolOverPipe(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})

	deadline := time.Now().Add(2 * time.Second)
	require.NoError(t, a.SetDeadline(deadline))
	require.NoError(t, b.SetDeadline(deadline))

	errs := make(chan error, 1)
	go func() {
		if err := WriteByte(a, 0xcd); err != nil {
			errs <- err
			return
		}
		if err := WriteBool(a, true); err != nil {
			errs <- err
			return
		}
		errs <- WriteBool(a, false)
	}()

	gotByte, err := ReadByte(b)
	require.NoError(t, err)
	require.Equal(t, byte(0xcd), gotByte)

	gotTrue, err := ReadBool(b)
	require.NoError(t, err)
	require.True(t, gotTrue)

	gotFalse, err := ReadBool(b)
	require.NoError(t, err)
	require.False(t, gotFalse)

	require.NoError(t, <-errs)
}

func TestReadBoolRejectsInvalidValue(t *testing.T) {
	got, err := ReadBool(bytes.NewReader([]byte{2}))

	require.False(t, got)
	require.ErrorContains(t, err, "invalid bool byte 2")
}
