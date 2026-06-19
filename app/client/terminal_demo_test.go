package client

import (
	"context"
	"testing"

	"github.com/Mikadore/mygosh/lib/service"
	"github.com/Mikadore/mygosh/lib/service/servicepb"
	sessionmux "github.com/Mikadore/mygosh/lib/session"
	"github.com/stretchr/testify/require"
)

func TestTerminalChannelHandlerRecordsExitStatus(t *testing.T) {
	handler := newTerminalChannelHandler()
	payload, err := service.MarshalPayload(&servicepb.ExitStatus{Code: 23})
	require.NoError(t, err)

	response := handler.OnRequest(context.Background(), nil, sessionmux.ChannelRequest{
		Type:    service.RequestTypeExitStatus,
		Payload: payload,
	})
	require.True(t, response.OK)

	status, err := handler.waitExitStatus(context.Background(), make(chan error))
	require.NoError(t, err)
	require.Equal(t, int32(23), status)
}

func TestTerminalChannelHandlerRejectsMalformedExitStatus(t *testing.T) {
	handler := newTerminalChannelHandler()
	response := handler.OnRequest(context.Background(), nil, sessionmux.ChannelRequest{
		Type:    service.RequestTypeExitStatus,
		Payload: []byte{0xff},
	})
	require.False(t, response.OK)

	_, err := handler.waitExitStatus(context.Background(), make(chan error))
	require.ErrorContains(t, err, "decode remote exit status")
}
