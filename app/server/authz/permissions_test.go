package authz

import (
	"context"
	"testing"

	usermodel "github.com/Mikadore/mygosh/lib/account"
	"github.com/stretchr/testify/require"
)

func TestConnectionPermissionsDefaultToDenyAndAreImmutable(t *testing.T) {
	authorization, credentials := authorizedCredentials(t, PermissionDecision{})
	permissions := credentials.Permissions()
	require.False(t, permissions.AllowSession())
	require.False(t, permissions.AllowShell())
	require.False(t, permissions.AllowExec())
	require.False(t, permissions.AllowPTY())

	_, err := authorization.AuthorizeChannel(context.Background(), credentials, ChannelAuthorizationRequest{Type: SessionChannelType})
	require.ErrorContains(t, err, "not permitted")

	authorization, credentials = authorizedCredentials(t, PermissionDecision{
		AllowSession:       true,
		AllowExec:          true,
		AllowedEnvironment: []string{"TERM", "LANG"},
	})
	copy := credentials.Permissions().AllowedEnvironment()
	copy[0] = "MUTATED"
	require.Equal(t, []string{"LANG", "TERM"}, credentials.Permissions().AllowedEnvironment())
}

func TestAuthorizeChannelAndLaunch(t *testing.T) {
	authorization, credentials := authorizedCredentials(t, PermissionDecision{
		AllowSession:       true,
		AllowShell:         true,
		AllowExec:          true,
		AllowPTY:           true,
		AllowedEnvironment: []string{"LANG", "TERM"},
	})
	channel, err := authorization.AuthorizeChannel(context.Background(), credentials, ChannelAuthorizationRequest{
		Type: SessionChannelType,
	})
	require.NoError(t, err)
	require.Equal(t, SessionChannelType, channel.Type())

	spec, err := authorization.AuthorizeLaunch(context.Background(), credentials, channel, LaunchRequest{
		Kind:    LaunchExec,
		Command: "printf hello",
		PTY:     &PTYRequest{Terminal: "xterm", Rows: 24, Columns: 80},
		Environment: map[string]string{
			"TERM": "xterm",
			"LANG": "C.UTF-8",
		},
	})
	require.NoError(t, err)
	require.Equal(t, LaunchExec, spec.Kind())
	require.Equal(t, "printf hello", spec.Command())
	require.Equal(t, "/bin/sh", spec.Executable())
	require.Equal(t, "/home/alice", spec.WorkingDirectory())
	require.Equal(t, map[string]string{"LANG": "C.UTF-8", "TERM": "xterm"}, spec.Environment())
	require.Equal(t, uint32(24), spec.PTY().Rows)

	environment := spec.Environment()
	environment["TERM"] = "mutated"
	require.Equal(t, "xterm", spec.Environment()["TERM"])
	account := spec.Account()
	account.HomeDir = "/tmp"
	require.Equal(t, "/home/alice", spec.Account().HomeDir)
}

func TestAuthorizeLaunchAppliesForcedCommandAndRejectsConstraints(t *testing.T) {
	authorization, credentials := authorizedCredentials(t, PermissionDecision{
		AllowSession:       true,
		AllowShell:         true,
		AllowExec:          true,
		ForcedCommand:      "restricted-command",
		AllowedEnvironment: []string{"LANG"},
	})
	channel, err := authorization.AuthorizeChannel(context.Background(), credentials, ChannelAuthorizationRequest{Type: SessionChannelType})
	require.NoError(t, err)

	spec, err := authorization.AuthorizeLaunch(context.Background(), credentials, channel, LaunchRequest{
		Kind:    LaunchExec,
		Command: "untrusted-command",
	})
	require.NoError(t, err)
	require.Equal(t, LaunchExec, spec.Kind())
	require.Equal(t, "restricted-command", spec.Command())

	_, err = authorization.AuthorizeLaunch(context.Background(), credentials, channel, LaunchRequest{
		Kind: LaunchShell,
		PTY:  &PTYRequest{Rows: 24, Columns: 80},
	})
	require.ErrorContains(t, err, "PTY")

	_, err = authorization.AuthorizeLaunch(context.Background(), credentials, channel, LaunchRequest{
		Kind:        LaunchExec,
		Command:     "true",
		Environment: map[string]string{"PATH": "/tmp"},
	})
	require.ErrorContains(t, err, "not permitted")
}

func TestPermissionPolicyRejectsIncoherentDecision(t *testing.T) {
	clientKey, verified := verifiedFixture(t, "alice")
	authorization, err := New(Config{
		Resolver: usermodel.ResolverFunc(func(context.Context, string) (usermodel.Account, error) {
			return testAccount(), nil
		}),
		AuthorizedKeysPaths: []string{writeAuthorizedKeys(t, clientKey.PublicKey())},
		PermissionPolicy: PermissionPolicyFunc(func(
			context.Context,
			ConnectionRequest,
			usermodel.Account,
			string,
		) (PermissionDecision, error) {
			return PermissionDecision{AllowExec: true}, nil
		}),
	})
	require.NoError(t, err)
	_, err = authorization.AuthorizeConnection(context.Background(), ConnectionRequest{VerifiedClient: verified})
	require.ErrorContains(t, err, "require session permission")
}

func authorizedCredentials(t *testing.T, decision PermissionDecision) (*Authz, ConnectionCredentials) {
	t.Helper()
	clientKey, verified := verifiedFixture(t, "alice")
	authorization, err := New(Config{
		Resolver: usermodel.ResolverFunc(func(context.Context, string) (usermodel.Account, error) {
			return testAccount(), nil
		}),
		AuthorizedKeysPaths: []string{writeAuthorizedKeys(t, clientKey.PublicKey())},
		PermissionPolicy: PermissionPolicyFunc(func(
			context.Context,
			ConnectionRequest,
			usermodel.Account,
			string,
		) (PermissionDecision, error) {
			return decision, nil
		}),
	})
	require.NoError(t, err)
	credentials, err := authorization.AuthorizeConnection(context.Background(), ConnectionRequest{VerifiedClient: verified})
	require.NoError(t, err)
	return authorization, credentials
}
