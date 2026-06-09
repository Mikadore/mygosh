package bincoder

import (
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
