package authz

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Mikadore/mygosh/app/securefiles"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/trust"
	usermodel "github.com/Mikadore/mygosh/lib/user"
	"github.com/rotisserie/eris"
)

const (
	AuthenticationMethodPublicKey = "public-key"
	AuthorizedKeysMaxSize         = 1 << 20
)

type ConnectionRequest struct {
	VerifiedClient auth.VerifiedClient
	PeerAddress    string
}

type SessionRequest struct {
	ChannelType string
	Payload     []byte
}

type SessionLease interface {
	Close() error
}

type AccountPolicy interface {
	AuthorizeAccount(ctx context.Context, request ConnectionRequest, account usermodel.Account, matchedSource string) error
}

type AccountPolicyFunc func(ctx context.Context, request ConnectionRequest, account usermodel.Account, matchedSource string) error

func (f AccountPolicyFunc) AuthorizeAccount(ctx context.Context, request ConnectionRequest, account usermodel.Account, matchedSource string) error {
	if f == nil {
		return nil
	}
	return f(ctx, request, usermodel.CloneAccount(account), matchedSource)
}

type SessionPolicy interface {
	OpenSession(ctx context.Context, credentials ConnectionCredentials, request SessionRequest) (SessionLease, error)
}

type SessionPolicyFunc func(ctx context.Context, credentials ConnectionCredentials, request SessionRequest) (SessionLease, error)

func (f SessionPolicyFunc) OpenSession(ctx context.Context, credentials ConnectionCredentials, request SessionRequest) (SessionLease, error) {
	if f == nil {
		return newNoopLease(), nil
	}
	request.Payload = append([]byte(nil), request.Payload...)
	return f(ctx, credentials, request)
}

type Config struct {
	Resolver            usermodel.Resolver
	AuthorizedKeysPaths []string
	AccountPolicy       AccountPolicy
	SessionPolicy       SessionPolicy
	Logger              *slog.Logger
}

type Authz struct {
	resolver            usermodel.Resolver
	authorizedKeysPaths []string
	accountPolicy       AccountPolicy
	sessionPolicy       SessionPolicy
	logger              *slog.Logger
}

func New(cfg Config) (*Authz, error) {
	if cfg.Resolver == nil {
		cfg.Resolver = usermodel.OSResolver{}
	}
	if len(cfg.AuthorizedKeysPaths) == 0 {
		return nil, eris.New("authorized_keys paths are required")
	}
	if cfg.AccountPolicy == nil {
		cfg.AccountPolicy = AccountPolicyFunc(nil)
	}
	if cfg.SessionPolicy == nil {
		cfg.SessionPolicy = SessionPolicyFunc(nil)
	}

	return &Authz{
		resolver:            cfg.Resolver,
		authorizedKeysPaths: append([]string(nil), cfg.AuthorizedKeysPaths...),
		accountPolicy:       cfg.AccountPolicy,
		sessionPolicy:       cfg.SessionPolicy,
		logger:              logging.Resolve(cfg.Logger),
	}, nil
}

func (a *Authz) AuthorizeConnection(ctx context.Context, request ConnectionRequest) (ConnectionCredentials, error) {
	if a == nil {
		return ConnectionCredentials{}, eris.New("server authorization is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ConnectionCredentials{}, err
	}

	verified := request.VerifiedClient
	username := verified.RequestedUsername()
	provenKey := verified.ProvenKey()
	if username == "" || !(&provenKey).IsSigning() {
		return ConnectionCredentials{}, eris.New("verified client proof is incomplete")
	}

	account, err := a.resolver.Resolve(ctx, username)
	if err != nil {
		return ConnectionCredentials{}, eris.Wrapf(err, "resolve account for requested user %q", username)
	}
	account = usermodel.CloneAccount(account)
	if err := validateAccount(account); err != nil {
		return ConnectionCredentials{}, eris.Wrap(err, "validate resolved account")
	}

	matchedSource, err := a.matchAuthorizedKey(ctx, account, provenKey)
	if err != nil {
		return ConnectionCredentials{}, err
	}
	if err := a.accountPolicy.AuthorizeAccount(ctx, request, account, matchedSource); err != nil {
		return ConnectionCredentials{}, eris.Wrap(err, "apply account policy")
	}

	credentials := newConnectionCredentials(request, account, matchedSource)
	if err := credentials.validate(); err != nil {
		return ConnectionCredentials{}, eris.Wrap(err, "validate connection credentials")
	}
	a.logger.Info(
		"authorized client connection",
		"requested_username", credentials.RequestedUsername(),
		"local_username", credentials.Account().Username,
		"uid", credentials.Account().UID(),
		"gid", credentials.Account().GID(),
		"source", credentials.MatchedSource(),
		"fingerprint", credentials.KeyFingerprint(),
	)
	return credentials, nil
}

func (a *Authz) OpenSession(ctx context.Context, credentials ConnectionCredentials, request SessionRequest) (SessionLease, error) {
	if a == nil {
		return nil, eris.New("server authorization is required")
	}
	if err := credentials.validate(); err != nil {
		return nil, eris.Wrap(err, "validate connection credentials")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	lease, err := a.sessionPolicy.OpenSession(ctx, credentials, request)
	if err != nil {
		return nil, eris.Wrap(err, "apply session policy")
	}
	if lease == nil {
		return nil, eris.New("session policy returned a nil lease")
	}
	return lease, nil
}

func (a *Authz) matchAuthorizedKey(ctx context.Context, account usermodel.Account, provedKey keys.PublicKey) (string, error) {
	var errs error
	keyCount := 0

	for _, configuredPath := range a.authorizedKeysPaths {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		resolved, anchor, relative, err := resolveAccountPath(account.HomeDir, configuredPath)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		a.logger.Debug("loading authorized_keys", "username", account.Username, "path", resolved)

		contents, err := securefiles.Read(anchor, relative, securefiles.Policy{
			OwnerID:         account.Id,
			MaxSize:         AuthorizedKeysMaxSize,
			AllowGlobalRead: true,
		})
		if err != nil {
			if !eris.Is(err, os.ErrNotExist) {
				errs = errors.Join(errs, eris.Wrapf(err, "read authorized_keys %q", resolved))
			}
			continue
		}

		authorizedKeys, err := trust.ParseAuthorizedKeys(contents)
		if err != nil {
			errs = errors.Join(errs, eris.Wrapf(err, "parse authorized_keys %q", resolved))
			continue
		}
		keyCount += len(authorizedKeys)
		if trust.MatchAuthorizedKey(authorizedKeys, provedKey) {
			return resolved, nil
		}
	}

	if errs != nil {
		return "", errs
	}
	if keyCount == 0 {
		return "", eris.Errorf("no authorized keys found for user %q", account.Username)
	}
	return "", eris.Errorf("client public key is not authorized for user %q", account.Username)
}

func resolveAccountPath(homeDir string, configuredPath string) (resolved string, anchor string, relative string, err error) {
	switch {
	case strings.HasPrefix(configuredPath, "~/"):
		if homeDir == "" {
			return "", "", "", eris.New("account home directory is required for ~ path")
		}
		relative = strings.TrimPrefix(configuredPath, "~/")
		return filepath.Join(homeDir, relative), homeDir, relative, nil
	case filepath.IsAbs(configuredPath):
		return configuredPath, filepath.Dir(configuredPath), filepath.Base(configuredPath), nil
	default:
		workingDir, getwdErr := os.Getwd()
		if getwdErr != nil {
			return "", "", "", eris.Wrap(getwdErr, "resolve relative authorized_keys path")
		}
		return filepath.Join(workingDir, configuredPath), workingDir, configuredPath, nil
	}
}

func validateAccount(account usermodel.Account) error {
	if account.Username == "" {
		return eris.New("resolved username is required")
	}
	if account.HomeDir == "" {
		return eris.New("account home directory is required")
	}
	return nil
}

type noopLease struct {
	once sync.Once
}

func newNoopLease() *noopLease {
	return &noopLease{}
}

func (l *noopLease) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {})
	return nil
}
