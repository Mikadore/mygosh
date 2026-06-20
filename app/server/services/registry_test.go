package services

import (
	"context"
	"testing"

	serverauthz "github.com/Mikadore/mygosh/app/server/authz"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/stretchr/testify/require"
)

func TestEmptyRegistryRejectsAllChannels(t *testing.T) {
	registry, err := NewRegistry(serverauthz.ConnectionCredentials{}, rejectingAuthorizer{})
	require.NoError(t, err)
	decision := registry.OnChannelOpen(context.Background(), session.ChannelOpenRequest{Type: "session"})
	require.False(t, decision.OK)
	require.Equal(t, "unsupported-channel-type", decision.Code)
}

func TestRegistryRejectsDuplicateServiceTypes(t *testing.T) {
	_, err := NewRegistry(
		serverauthz.ConnectionCredentials{},
		rejectingAuthorizer{},
		testService{},
		testService{},
	)
	require.ErrorContains(t, err, "duplicate service")
}

type rejectingAuthorizer struct{}

func (rejectingAuthorizer) AuthorizeChannel(
	context.Context,
	serverauthz.ConnectionCredentials,
	serverauthz.ChannelAuthorizationRequest,
) (serverauthz.AuthorizedChannel, error) {
	return serverauthz.AuthorizedChannel{}, context.Canceled
}

type testService struct{}

func (testService) ChannelType() string {
	return "session"
}

func (testService) Open(
	context.Context,
	serverauthz.ConnectionCredentials,
	serverauthz.AuthorizedChannel,
	session.ChannelOpenRequest,
) (session.ChannelOpenDecision, error) {
	return session.ChannelOpenDecision{OK: true}, nil
}
