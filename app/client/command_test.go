package client

import (
	"errors"
	"os"
	"testing"

	commandprotocol "github.com/Mikadore/mygosh/lib/command"
	"github.com/stretchr/testify/require"
)

func TestBuildStartRequestCLISelection(t *testing.T) {
	t.Run("exec defaults to no PTY", func(t *testing.T) {
		request, _, err := buildStartRequest(ConnectArgs{
			Command: []string{"printf", "hello"},
		})
		require.NoError(t, err)
		require.Equal(t, commandprotocol.StartExec, request.Kind)
		require.Equal(t, "printf hello", request.Command)
		require.Nil(t, request.PTY)
	})

	t.Run("force PTY", func(t *testing.T) {
		t.Setenv("TERM", "xterm-test")
		request, _, err := buildStartRequest(ConnectArgs{
			Command:  []string{"top"},
			ForcePTY: true,
		})
		require.NoError(t, err)
		require.NotNil(t, request.PTY)
		require.Equal(t, "xterm-test", request.PTY.Terminal)
		require.Positive(t, request.PTY.Rows)
		require.Positive(t, request.PTY.Columns)
	})

	t.Run("disable PTY", func(t *testing.T) {
		request, _, err := buildStartRequest(ConnectArgs{DisablePTY: true})
		require.NoError(t, err)
		require.Equal(t, commandprotocol.StartShell, request.Kind)
		require.Nil(t, request.PTY)
	})
}

func TestRequestedEnvironment(t *testing.T) {
	t.Setenv("FORWARD_ME", "local-value")
	environment, err := requestedEnvironment([]string{"FORWARD_ME", "LANG=C.UTF-8"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"FORWARD_ME": "local-value",
		"LANG":       "C.UTF-8",
	}, environment)

	_, err = requestedEnvironment([]string{"MISSING_ENV_FOR_MY_GOSH_TEST"})
	require.ErrorContains(t, err, "is not set")
	_, err = requestedEnvironment([]string{"LANG=C", "LANG=en_US"})
	require.ErrorContains(t, err, "more than once")
}

func TestNormalizeRemoteExit(t *testing.T) {
	err := normalizeRemoteExit(&commandprotocol.ExitStatusError{Status: 42})
	var remote *RemoteExitError
	require.ErrorAs(t, err, &remote)
	require.Equal(t, 42, remote.ExitCode())
	require.True(t, remote.Silent())

	err = normalizeRemoteExit(&commandprotocol.ExitSignalError{Signal: "SIGTERM"})
	require.ErrorAs(t, err, &remote)
	require.Equal(t, 143, remote.ExitCode())
	require.False(t, remote.Silent())

	err = normalizeRemoteExit(errors.New("runtime"))
	require.ErrorAs(t, err, &remote)
	require.Equal(t, 255, remote.ExitCode())
}

func TestRequestedEnvironmentReadsCurrentProcess(t *testing.T) {
	const name = "MYGOSH_ENV_TEST"
	require.NoError(t, os.Setenv(name, "value"))
	t.Cleanup(func() { _ = os.Unsetenv(name) })
	got, err := requestedEnvironment([]string{name})
	require.NoError(t, err)
	require.Equal(t, "value", got[name])
}
