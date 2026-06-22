package authz

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mikadore/mygosh/app/securefiles"
	usermodel "github.com/Mikadore/mygosh/lib/account"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/trust"
	"github.com/rotisserie/eris"
)

const (
	AuthenticationMethodPublicKey = "public-key"
	AuthorizedKeysMaxSize         = 8 << 20
)

type ConnectionRequest struct {
	VerifiedClient auth.VerifiedClient
	PeerAddress    string
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

type Config struct {
	Resolver            usermodel.Resolver
	AuthorizedKeysPaths []string
	AccountPolicy       AccountPolicy
	PermissionPolicy    PermissionPolicy
	AuditLogger         *slog.Logger
}

type Authz struct {
	resolver            usermodel.Resolver
	authorizedKeysPaths []string
	accountPolicy       AccountPolicy
	permissionPolicy    PermissionPolicy
	auditLogger         *slog.Logger
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
	if cfg.PermissionPolicy == nil {
		cfg.PermissionPolicy = PermissionPolicyFunc(nil)
	}

	return &Authz{
		resolver:            cfg.Resolver,
		authorizedKeysPaths: append([]string(nil), cfg.AuthorizedKeysPaths...),
		accountPolicy:       cfg.AccountPolicy,
		permissionPolicy:    cfg.PermissionPolicy,
		auditLogger:         resolveAuditLogger(cfg.AuditLogger),
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
	if username == "" || provenKey.Validate() != nil {
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

	matched, err := a.matchAuthorizedKey(ctx, account, provenKey)
	if err != nil {
		return ConnectionCredentials{}, err
	}
	if err := a.accountPolicy.AuthorizeAccount(ctx, request, account, matched.source); err != nil {
		return ConnectionCredentials{}, eris.Wrap(err, "apply account policy")
	}
	permissionDecision, err := a.permissionPolicy.ResolvePermissions(ctx, request, account, matched.source)
	if err != nil {
		return ConnectionCredentials{}, eris.Wrap(err, "resolve connection permissions")
	}
	permissionDecision, err = applyMatchedKeyConstraints(permissionDecision, matched.constraints)
	if err != nil {
		return ConnectionCredentials{}, eris.Wrap(err, "apply authorized-key constraints")
	}
	permissions, err := newConnectionPermissions(permissionDecision)
	if err != nil {
		return ConnectionCredentials{}, eris.Wrap(err, "validate connection permissions")
	}

	credentials := newConnectionCredentials(request, account, matched.source, matched.constraints, permissions)
	if err := credentials.validate(); err != nil {
		return ConnectionCredentials{}, eris.Wrap(err, "validate connection credentials")
	}
	a.auditLogger.Info(
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

type matchedAuthorizedKey struct {
	source      string
	constraints MatchedKeyConstraints
}

func (a *Authz) matchAuthorizedKey(ctx context.Context, account usermodel.Account, provedKey keys.PublicKey) (matchedAuthorizedKey, error) {
	var errs error
	foundAuthorizedKeys := false

	for _, configuredPath := range a.authorizedKeysPaths {
		if err := ctx.Err(); err != nil {
			return matchedAuthorizedKey{}, err
		}

		resolved, anchor, relative, err := resolveAccountPath(account.HomeDir, configuredPath)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		slog.Default().With("component", "server-authz").Debug(
			"loading authorized_keys",
			"username", account.Username,
			"path", resolved,
		)

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

		authorizedKeysFile, err := trust.ParseAuthorizedKeys(contents)
		if err != nil {
			errs = errors.Join(errs, eris.Wrapf(err, "parse authorized_keys %q", resolved))
			continue
		}
		if _, ok := authorizedKeysFile.Match(func(*trust.AuthorizedKeyEntry) bool { return true }); ok {
			foundAuthorizedKeys = true
		}
		if entry, ok := authorizedKeysFile.Match(func(entry *trust.AuthorizedKeyEntry) bool {
			return entry.Key.Equal(provedKey)
		}); ok {
			if errs != nil {
				return matchedAuthorizedKey{}, errs
			}
			constraints, err := entry.Constraints()
			if err != nil {
				return matchedAuthorizedKey{}, eris.Wrapf(err, "resolve authorized_keys constraints from %q", resolved)
			}
			return matchedAuthorizedKey{
				source:      resolved,
				constraints: newMatchedKeyConstraints(constraints),
			}, nil
		}
	}

	if errs != nil {
		return matchedAuthorizedKey{}, errs
	}
	if !foundAuthorizedKeys {
		return matchedAuthorizedKey{}, eris.Errorf("no authorized keys found for user %q", account.Username)
	}
	return matchedAuthorizedKey{}, eris.Errorf("client public key is not authorized for user %q", account.Username)
}

func resolveAuditLogger(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.New(slog.DiscardHandler)
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
