package command

import (
	"context"
	"testing"

	serverauthz "github.com/Mikadore/mygosh/app/server/authz"
	serverprocess "github.com/Mikadore/mygosh/app/server/process"
	commandprotocol "github.com/Mikadore/mygosh/lib/command"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/stretchr/testify/require"
)

func TestServiceAcceptsOnlyEmptyCommandChannelOpen(t *testing.T) {
	service, err := NewService(stubLaunchAuthorizer{}, stubRunner{})
	require.NoError(t, err)

	decision, err := service.Open(
		context.Background(),
		serverauthz.ConnectionCredentials{},
		serverauthz.AuthorizedChannel{},
		session.ChannelOpenRequest{Type: commandprotocol.ChannelType},
	)
	require.NoError(t, err)
	require.True(t, decision.OK)
	require.NotNil(t, decision.Handler)

	_, err = service.Open(
		context.Background(),
		serverauthz.ConnectionCredentials{},
		serverauthz.AuthorizedChannel{},
		session.ChannelOpenRequest{Type: commandprotocol.ChannelType, Payload: []byte("unexpected")},
	)
	require.ErrorContains(t, err, "payload must be empty")
}

func TestCommandStartTranslationBindsPTYTerminalToEnvironment(t *testing.T) {
	launch, err := toLaunchRequest(commandprotocol.StartRequest{
		Kind: commandprotocol.StartShell,
		PTY:  &commandprotocol.PTYRequest{Terminal: "xterm", Rows: 24, Columns: 80},
	})
	require.NoError(t, err)
	require.Equal(t, serverauthz.LaunchShell, launch.Kind)
	require.Equal(t, "xterm", launch.Environment["TERM"])
	require.Equal(t, uint32(24), launch.PTY.Rows)

	_, err = toLaunchRequest(commandprotocol.StartRequest{
		Kind:        commandprotocol.StartShell,
		PTY:         &commandprotocol.PTYRequest{Terminal: "xterm", Rows: 24, Columns: 80},
		Environment: map[string]string{"TERM": "vt100"},
	})
	require.ErrorContains(t, err, "conflicts")
}

type stubLaunchAuthorizer struct{}

func (stubLaunchAuthorizer) AuthorizeLaunch(
	context.Context,
	serverauthz.ConnectionCredentials,
	serverauthz.AuthorizedChannel,
	serverauthz.LaunchRequest,
) (serverauthz.AuthorizedLaunchSpec, error) {
	return serverauthz.AuthorizedLaunchSpec{}, nil
}

type stubRunner struct{}

func (stubRunner) Start(context.Context, serverprocess.Spec) (commandprotocol.RunningProcess, error) {
	return nil, nil
}
