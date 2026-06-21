package authz

import (
	"path/filepath"

	usermodel "github.com/Mikadore/mygosh/lib/account"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/rotisserie/eris"
)

type credentialIdentity struct{}

type ConnectionCredentials struct {
	authenticationMethod string
	keyFingerprint       string
	requestedUsername    string
	peerAddress          string
	provedKey            keys.PublicKey
	account              usermodel.Account
	matchedSource        string
	permissions          ConnectionPermissions
	identityToken        *credentialIdentity
}

func newConnectionCredentials(
	request ConnectionRequest,
	account usermodel.Account,
	matchedSource string,
	permissions ConnectionPermissions,
) ConnectionCredentials {
	verified := request.VerifiedClient
	provedKey := verified.ProvenKey()
	return ConnectionCredentials{
		authenticationMethod: AuthenticationMethodPublicKey,
		keyFingerprint:       provedKey.FingerprintSHA256(),
		requestedUsername:    verified.RequestedUsername(),
		peerAddress:          request.PeerAddress,
		provedKey:            provedKey.Clone(),
		account:              usermodel.CloneAccount(account),
		matchedSource:        matchedSource,
		permissions:          cloneConnectionPermissions(permissions),
		identityToken:        &credentialIdentity{},
	}
}

func (c ConnectionCredentials) AuthenticationMethod() string {
	return c.authenticationMethod
}

func (c ConnectionCredentials) KeyFingerprint() string {
	return c.keyFingerprint
}

func (c ConnectionCredentials) RequestedUsername() string {
	return c.requestedUsername
}

func (c ConnectionCredentials) PeerAddress() string {
	return c.peerAddress
}

func (c ConnectionCredentials) ProvedKey() keys.PublicKey {
	return c.provedKey.Clone()
}

func (c ConnectionCredentials) Account() usermodel.Account {
	return usermodel.CloneAccount(c.account)
}

func (c ConnectionCredentials) MatchedSource() string {
	return c.matchedSource
}

func (c ConnectionCredentials) Permissions() ConnectionPermissions {
	return cloneConnectionPermissions(c.permissions)
}

func (c ConnectionCredentials) identity() *credentialIdentity {
	return c.identityToken
}

func (c ConnectionCredentials) validate() error {
	if c.authenticationMethod == "" {
		return eris.New("authentication method is required")
	}
	if c.requestedUsername == "" {
		return eris.New("requested username is required")
	}
	if err := c.provedKey.Validate(); err != nil {
		return eris.Wrap(err, "proved client key")
	}
	if c.keyFingerprint == "" {
		return eris.New("client key fingerprint is required")
	}
	if err := validateAccount(c.account); err != nil {
		return err
	}
	if !filepath.IsAbs(c.account.HomeDir) {
		return eris.New("account home directory must be absolute")
	}
	if c.matchedSource == "" {
		return eris.New("matched policy source is required")
	}
	if err := c.permissions.validate(); err != nil {
		return eris.Wrap(err, "connection permissions")
	}
	if (c.permissions.allowShell || c.permissions.allowExec) && !filepath.IsAbs(c.account.LoginShell) {
		return eris.New("permitted launch requires an absolute account login shell")
	}
	if c.identityToken == nil {
		return eris.New("credential identity token is required")
	}
	return nil
}
