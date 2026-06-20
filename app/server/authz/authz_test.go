package authz

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	usermodel "github.com/Mikadore/mygosh/lib/user"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestAuthorizeConnectionBuildsImmutableCredentials(t *testing.T) {
	clientKey, verified := verifiedFixture(t, "alice")
	account := testAccount()
	account.SupplementaryGroups = []usermodel.Group{{Id: 23, Name: "staff"}}
	path := writeAuthorizedKeys(t, clientKey.PublicKey())

	var policyCalls atomic.Int32
	authorization, err := New(Config{
		Resolver: usermodel.ResolverFunc(func(_ context.Context, username string) (usermodel.Account, error) {
			require.Equal(t, "alice", username)
			return account, nil
		}),
		AuthorizedKeysPaths: []string{path},
		AccountPolicy: AccountPolicyFunc(func(_ context.Context, request ConnectionRequest, got usermodel.Account, source string) error {
			policyCalls.Add(1)
			require.Equal(t, "peer:42022", request.PeerAddress)
			require.Equal(t, account, got)
			require.Equal(t, path, source)
			return nil
		}),
	})
	require.NoError(t, err)

	credentials, err := authorization.AuthorizeConnection(context.Background(), ConnectionRequest{
		VerifiedClient: verified,
		PeerAddress:    "peer:42022",
	})
	require.NoError(t, err)
	require.Equal(t, int32(1), policyCalls.Load())
	require.Equal(t, AuthenticationMethodPublicKey, credentials.AuthenticationMethod())
	require.Equal(t, "alice", credentials.RequestedUsername())
	require.Equal(t, clientKey.PublicKey().FingerprintSHA256(), credentials.KeyFingerprint())
	require.Equal(t, clientKey.PublicKey(), credentials.ProvedKey())
	require.Equal(t, account, credentials.Account())
	require.Equal(t, path, credentials.MatchedSource())

	mutableKey := credentials.ProvedKey()
	mutableKey.Bytes[0] ^= 0xff
	mutableAccount := credentials.Account()
	mutableAccount.SupplementaryGroups[0].Id++
	require.Equal(t, clientKey.PublicKey(), credentials.ProvedKey())
	require.Equal(t, account, credentials.Account())
}

func TestAuthorizeConnectionExpandsHomeAndSkipsMissingFiles(t *testing.T) {
	clientKey, verified := verifiedFixture(t, "alice")
	homeDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(homeDir, ".mygosh"), 0o700))
	path := filepath.Join(homeDir, ".mygosh", "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte(authorizedKeysLine(t, clientKey.PublicKey())+"\n"), 0o644))

	account := testAccount()
	account.HomeDir = homeDir
	authorization, err := New(Config{
		Resolver: usermodel.ResolverFunc(func(context.Context, string) (usermodel.Account, error) {
			return account, nil
		}),
		AuthorizedKeysPaths: []string{"~/.ssh/missing", "~/.mygosh/authorized_keys"},
	})
	require.NoError(t, err)

	credentials, err := authorization.AuthorizeConnection(context.Background(), ConnectionRequest{VerifiedClient: verified})
	require.NoError(t, err)
	require.Equal(t, path, credentials.MatchedSource())
	lease, err := authorization.OpenSession(context.Background(), credentials, SessionRequest{ChannelType: "session"})
	require.NoError(t, err)
	require.NoError(t, lease.Close())
	require.NoError(t, lease.Close())
}

func TestAuthorizeConnectionRejectsMismatchAndMalformedFile(t *testing.T) {
	_, verified := verifiedFixture(t, "alice")
	otherKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	account := testAccount()

	t.Run("mismatch", func(t *testing.T) {
		authorization, err := New(Config{
			Resolver: usermodel.ResolverFunc(func(context.Context, string) (usermodel.Account, error) {
				return account, nil
			}),
			AuthorizedKeysPaths: []string{writeAuthorizedKeys(t, otherKey.PublicKey())},
		})
		require.NoError(t, err)
		_, err = authorization.AuthorizeConnection(context.Background(), ConnectionRequest{VerifiedClient: verified})
		require.ErrorContains(t, err, "not authorized")
	})

	t.Run("malformed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authorized_keys")
		require.NoError(t, os.WriteFile(path, []byte("not a valid authorized key\n"), 0o600))
		authorization, err := New(Config{
			Resolver: usermodel.ResolverFunc(func(context.Context, string) (usermodel.Account, error) {
				return account, nil
			}),
			AuthorizedKeysPaths: []string{path},
		})
		require.NoError(t, err)
		_, err = authorization.AuthorizeConnection(context.Background(), ConnectionRequest{VerifiedClient: verified})
		require.ErrorContains(t, err, "parse authorized_keys")
	})
}

func TestAuthorizeConnectionEnforcesAuthorizedKeysFilePolicy(t *testing.T) {
	clientKey, verified := verifiedFixture(t, "alice")
	account := testAccount()

	authorizePath := func(t *testing.T, path string) error {
		t.Helper()
		authorization, err := New(Config{
			Resolver: usermodel.ResolverFunc(func(context.Context, string) (usermodel.Account, error) {
				return account, nil
			}),
			AuthorizedKeysPaths: []string{path},
		})
		require.NoError(t, err)
		_, err = authorization.AuthorizeConnection(context.Background(), ConnectionRequest{VerifiedClient: verified})
		return err
	}

	t.Run("group write", func(t *testing.T) {
		path := writeAuthorizedKeys(t, clientKey.PublicKey())
		require.NoError(t, os.Chmod(path, 0o620))
		require.ErrorContains(t, authorizePath(t, path), "write permission")
	})

	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		require.NoError(t, os.WriteFile(target, []byte(authorizedKeysLine(t, clientKey.PublicKey())+"\n"), 0o600))
		link := filepath.Join(dir, "authorized_keys")
		require.NoError(t, os.Symlink("target", link))
		require.Error(t, authorizePath(t, link))
	})

	t.Run("maximum size", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authorized_keys")
		require.NoError(t, os.WriteFile(path, make([]byte, AuthorizedKeysMaxSize+1), 0o600))
		require.ErrorContains(t, authorizePath(t, path), "exceeds maximum")
	})
}

func TestOpenSessionDelegatesAndLeaseCloses(t *testing.T) {
	clientKey, verified := verifiedFixture(t, "alice")
	account := testAccount()
	path := writeAuthorizedKeys(t, clientKey.PublicKey())
	lease := &countingLease{}

	authorization, err := New(Config{
		Resolver: usermodel.ResolverFunc(func(context.Context, string) (usermodel.Account, error) {
			return account, nil
		}),
		AuthorizedKeysPaths: []string{path},
		SessionPolicy: SessionPolicyFunc(func(_ context.Context, credentials ConnectionCredentials, request SessionRequest) (SessionLease, error) {
			require.Equal(t, "alice", credentials.RequestedUsername())
			require.Equal(t, "session", request.ChannelType)
			return lease, nil
		}),
	})
	require.NoError(t, err)
	credentials, err := authorization.AuthorizeConnection(context.Background(), ConnectionRequest{VerifiedClient: verified})
	require.NoError(t, err)

	got, err := authorization.OpenSession(context.Background(), credentials, SessionRequest{ChannelType: "session"})
	require.NoError(t, err)
	require.Same(t, lease, got)
	require.NoError(t, got.Close())
	require.Equal(t, int32(1), lease.closed.Load())
}

type countingLease struct {
	closed atomic.Int32
}

func (l *countingLease) Close() error {
	l.closed.Add(1)
	return nil
}

func verifiedFixture(t *testing.T, username string) (keys.Keypair, auth.VerifiedClient) {
	t.Helper()
	clientKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	serverKey, err := keys.GenerateEd25519()
	require.NoError(t, err)
	verified, err := auth.NewVerifiedClient("server.example.test", username, clientKey.PublicKey(), serverKey.PublicKey())
	require.NoError(t, err)
	return clientKey, verified
}

func testAccount() usermodel.Account {
	return usermodel.Account{
		Username: "alice",
		Id:       uint32(os.Geteuid()),
		PrimaryGroup: usermodel.Group{
			Id: uint32(os.Getegid()),
		},
		HomeDir:    "/home/alice",
		LoginShell: "/bin/sh",
	}
}

func writeAuthorizedKeys(t *testing.T, publicKey keys.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte(authorizedKeysLine(t, publicKey)+"\n"), 0o600))
	return path
}

func authorizedKeysLine(t *testing.T, publicKey keys.PublicKey) string {
	t.Helper()
	sshPublicKey, err := ssh.NewPublicKey(ed25519.PublicKey(publicKey.Bytes))
	require.NoError(t, err)
	return sshPublicKey.Type() + " " + base64.StdEncoding.EncodeToString(sshPublicKey.Marshal())
}
