package authz

import (
	"context"
	"slices"
	"strings"

	usermodel "github.com/Mikadore/mygosh/lib/account"
	"github.com/rotisserie/eris"
)

// PermissionDecision is the mutable policy output accepted at the application
// boundary. It is validated and copied into immutable ConnectionPermissions.
type PermissionDecision struct {
	AllowSession       bool
	AllowShell         bool
	AllowExec          bool
	AllowPTY           bool
	ForcedCommand      string
	AllowedEnvironment []string
}

type PermissionPolicy interface {
	ResolvePermissions(
		ctx context.Context,
		request ConnectionRequest,
		account usermodel.Account,
		matchedSource string,
	) (PermissionDecision, error)
}

type PermissionPolicyFunc func(
	ctx context.Context,
	request ConnectionRequest,
	account usermodel.Account,
	matchedSource string,
) (PermissionDecision, error)

func (f PermissionPolicyFunc) ResolvePermissions(
	ctx context.Context,
	request ConnectionRequest,
	account usermodel.Account,
	matchedSource string,
) (PermissionDecision, error) {
	if f == nil {
		return PermissionDecision{}, nil
	}
	return f(ctx, request, usermodel.CloneAccount(account), matchedSource)
}

// ConnectionPermissions is an immutable connection-wide permission snapshot.
type ConnectionPermissions struct {
	allowSession       bool
	allowShell         bool
	allowExec          bool
	allowPTY           bool
	forcedCommand      string
	allowedEnvironment []string
}

func newConnectionPermissions(decision PermissionDecision) (ConnectionPermissions, error) {
	decision.ForcedCommand = strings.TrimSpace(decision.ForcedCommand)
	if strings.ContainsRune(decision.ForcedCommand, '\x00') {
		return ConnectionPermissions{}, eris.New("forced command contains NUL")
	}
	if len(decision.ForcedCommand) > 24<<10 {
		return ConnectionPermissions{}, eris.New("forced command exceeds maximum size")
	}
	if (decision.AllowShell || decision.AllowExec || decision.AllowPTY || decision.ForcedCommand != "") && !decision.AllowSession {
		return ConnectionPermissions{}, eris.New("session sub-permissions require session permission")
	}
	if decision.ForcedCommand != "" && !decision.AllowShell && !decision.AllowExec {
		return ConnectionPermissions{}, eris.New("forced command requires shell or exec permission")
	}
	if decision.AllowPTY && !decision.AllowShell && !decision.AllowExec {
		return ConnectionPermissions{}, eris.New("PTY permission requires shell or exec permission")
	}

	allowed := make([]string, 0, len(decision.AllowedEnvironment))
	if len(decision.AllowedEnvironment) > 128 {
		return ConnectionPermissions{}, eris.New("too many allowed environment variables")
	}
	seen := make(map[string]struct{}, len(decision.AllowedEnvironment))
	for _, name := range decision.AllowedEnvironment {
		name = strings.TrimSpace(name)
		if err := validateEnvironmentName(name); err != nil {
			return ConnectionPermissions{}, err
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		allowed = append(allowed, name)
	}
	slices.Sort(allowed)

	return ConnectionPermissions{
		allowSession:       decision.AllowSession,
		allowShell:         decision.AllowShell,
		allowExec:          decision.AllowExec,
		allowPTY:           decision.AllowPTY,
		forcedCommand:      decision.ForcedCommand,
		allowedEnvironment: allowed,
	}, nil
}

func (p ConnectionPermissions) AllowSession() bool {
	return p.allowSession
}

func (p ConnectionPermissions) AllowShell() bool {
	return p.allowShell
}

func (p ConnectionPermissions) AllowExec() bool {
	return p.allowExec
}

func (p ConnectionPermissions) AllowPTY() bool {
	return p.allowPTY
}

func (p ConnectionPermissions) ForcedCommand() string {
	return p.forcedCommand
}

func (p ConnectionPermissions) AllowedEnvironment() []string {
	return append([]string(nil), p.allowedEnvironment...)
}

func cloneConnectionPermissions(p ConnectionPermissions) ConnectionPermissions {
	p.allowedEnvironment = append([]string(nil), p.allowedEnvironment...)
	return p
}

func (p ConnectionPermissions) validate() error {
	_, err := newConnectionPermissions(PermissionDecision{
		AllowSession:       p.allowSession,
		AllowShell:         p.allowShell,
		AllowExec:          p.allowExec,
		AllowPTY:           p.allowPTY,
		ForcedCommand:      p.forcedCommand,
		AllowedEnvironment: p.allowedEnvironment,
	})
	return err
}

func validateEnvironmentName(name string) error {
	if name == "" {
		return eris.New("environment variable name is required")
	}
	if strings.ContainsAny(name, "=\x00") {
		return eris.Errorf("invalid environment variable name %q", name)
	}
	if len(name) > 256 {
		return eris.Errorf("environment variable name %q exceeds maximum size", name)
	}
	return nil
}
