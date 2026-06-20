package authz

import (
	"github.com/Mikadore/mygosh/lib/keys"
	usermodel "github.com/Mikadore/mygosh/lib/user"
	"github.com/rotisserie/eris"
)

type ConnectionCredentials struct {
	authenticationMethod string
	keyFingerprint       string
	hostIdentity         string
	requestedUsername    string
	peerAddress          string
	provedKey            keys.PublicKey
	serverKey            keys.PublicKey
	account              usermodel.Account
	matchedSource        string
}

func newConnectionCredentials(request ConnectionRequest, account usermodel.Account, matchedSource string) ConnectionCredentials {
	verified := request.VerifiedClient
	provedKey := verified.ProvenKey()
	return ConnectionCredentials{
		authenticationMethod: AuthenticationMethodPublicKey,
		keyFingerprint:       provedKey.FingerprintSHA256(),
		hostIdentity:         verified.HostIdentity(),
		requestedUsername:    verified.RequestedUsername(),
		peerAddress:          request.PeerAddress,
		provedKey:            clonePublicKey(provedKey),
		serverKey:            clonePublicKey(verified.ServerKey()),
		account:              usermodel.CloneAccount(account),
		matchedSource:        matchedSource,
	}
}

func (c ConnectionCredentials) AuthenticationMethod() string {
	return c.authenticationMethod
}

func (c ConnectionCredentials) KeyFingerprint() string {
	return c.keyFingerprint
}

func (c ConnectionCredentials) HostIdentity() string {
	return c.hostIdentity
}

func (c ConnectionCredentials) RequestedUsername() string {
	return c.requestedUsername
}

func (c ConnectionCredentials) PeerAddress() string {
	return c.peerAddress
}

func (c ConnectionCredentials) ProvedKey() keys.PublicKey {
	return clonePublicKey(c.provedKey)
}

func (c ConnectionCredentials) ServerKey() keys.PublicKey {
	return clonePublicKey(c.serverKey)
}

func (c ConnectionCredentials) Account() usermodel.Account {
	return usermodel.CloneAccount(c.account)
}

func (c ConnectionCredentials) MatchedSource() string {
	return c.matchedSource
}

func (c ConnectionCredentials) validate() error {
	if c.authenticationMethod == "" {
		return eris.New("authentication method is required")
	}
	if c.requestedUsername == "" {
		return eris.New("requested username is required")
	}
	if !(&c.provedKey).IsSigning() {
		return eris.New("proved client key is invalid")
	}
	if !(&c.serverKey).IsSigning() {
		return eris.New("server key is invalid")
	}
	if c.keyFingerprint == "" {
		return eris.New("client key fingerprint is required")
	}
	if err := validateAccount(c.account); err != nil {
		return err
	}
	if c.matchedSource == "" {
		return eris.New("matched policy source is required")
	}
	return nil
}

func clonePublicKey(key keys.PublicKey) keys.PublicKey {
	return keys.PublicKey{
		Algorithm: key.Algorithm,
		Bytes:     append([]byte(nil), key.Bytes...),
		Comment:   key.Comment,
	}
}
