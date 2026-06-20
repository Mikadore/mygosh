package session

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLimitsDefaultsAndHardMaxima(t *testing.T) {
	limits := (Limits{}).withDefaults()
	require.Equal(t, uint32(64), limits.MaxChannels)
	require.Equal(t, uint32(32), limits.MaxPendingOpens)
	require.Equal(t, uint32(1024), limits.MaxPendingChannelRequests)
	require.Equal(t, uint64(16<<20), limits.MaxQueuedBytesTotal)
	require.Equal(t, uint32(16<<10), limits.MaxControlPayload)
	require.NoError(t, limits.Validate())

	limits.MaxChannels = hardMaxChannels + 1
	require.ErrorContains(t, limits.Validate(), "hard maximum")
}

func TestLimitsRejectIncoherentRelationships(t *testing.T) {
	require.ErrorContains(t, (Limits{
		MaxChannels:     1,
		MaxPendingOpens: 2,
	}).Validate(), "pending opens")
	require.ErrorContains(t, (Limits{
		MaxQueuedFramesPerChannel: 2,
		MaxQueuedFramesTotal:      1,
	}).Validate(), "per-channel queued frame")
}
