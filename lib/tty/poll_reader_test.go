//go:build linux || darwin || freebsd || openbsd || netbsd

package tty

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPollReaderCancellationDoesNotCloseOriginalInput(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	require.NoError(t, err)
	defer readEnd.Close()  //nolint:errcheck
	defer writeEnd.Close() //nolint:errcheck

	reader, err := NewPollReader(readEnd)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := reader.Read(ctx, make([]byte, 1))
		result <- err
	}()
	cancel()

	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("poll reader did not unblock on cancellation")
	}
	require.NoError(t, reader.Close())

	_, err = writeEnd.Write([]byte("x"))
	require.NoError(t, err)
	buffer := make([]byte, 1)
	_, err = readEnd.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, []byte("x"), buffer)

	_, err = reader.Read(context.Background(), make([]byte, 1))
	require.True(t, errors.Is(err, os.ErrClosed))
}
