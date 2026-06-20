package authz

import (
	"context"
	"path/filepath"
	"slices"
	"strings"

	usermodel "github.com/Mikadore/mygosh/lib/account"
	"github.com/rotisserie/eris"
)

const SessionChannelType = "session"

type ChannelAuthorizationRequest struct {
	Type    string
	Payload []byte
}

type AuthorizedChannel struct {
	channelType        string
	credentialIdentity *credentialIdentity
}

func (c AuthorizedChannel) Type() string {
	return c.channelType
}

type ChannelAuthorizer interface {
	AuthorizeChannel(
		ctx context.Context,
		credentials ConnectionCredentials,
		request ChannelAuthorizationRequest,
	) (AuthorizedChannel, error)
}

type LaunchKind string

const (
	LaunchShell LaunchKind = "shell"
	LaunchExec  LaunchKind = "exec"
)

type PTYRequest struct {
	Terminal string
	Rows     uint32
	Columns  uint32
}

type LaunchRequest struct {
	Kind        LaunchKind
	Command     string
	PTY         *PTYRequest
	Environment map[string]string
}

type AuthorizedLaunchSpec struct {
	kind             LaunchKind
	command          string
	executable       string
	workingDirectory string
	pty              *PTYRequest
	environment      map[string]string
	account          usermodel.Account
}

func (s AuthorizedLaunchSpec) Kind() LaunchKind {
	return s.kind
}

func (s AuthorizedLaunchSpec) Command() string {
	return s.command
}

func (s AuthorizedLaunchSpec) Executable() string {
	return s.executable
}

func (s AuthorizedLaunchSpec) WorkingDirectory() string {
	return s.workingDirectory
}

func (s AuthorizedLaunchSpec) PTY() *PTYRequest {
	if s.pty == nil {
		return nil
	}
	copy := *s.pty
	return &copy
}

func (s AuthorizedLaunchSpec) Environment() map[string]string {
	environment := make(map[string]string, len(s.environment))
	for name, value := range s.environment {
		environment[name] = value
	}
	return environment
}

func (s AuthorizedLaunchSpec) Account() usermodel.Account {
	return usermodel.CloneAccount(s.account)
}

type LaunchAuthorizer interface {
	AuthorizeLaunch(
		ctx context.Context,
		credentials ConnectionCredentials,
		channel AuthorizedChannel,
		request LaunchRequest,
	) (AuthorizedLaunchSpec, error)
}

func (a *Authz) AuthorizeChannel(
	ctx context.Context,
	credentials ConnectionCredentials,
	request ChannelAuthorizationRequest,
) (AuthorizedChannel, error) {
	if a == nil {
		return AuthorizedChannel{}, eris.New("server authorization is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AuthorizedChannel{}, err
	}
	if err := credentials.validate(); err != nil {
		return AuthorizedChannel{}, eris.Wrap(err, "validate connection credentials")
	}
	if request.Type != SessionChannelType {
		return AuthorizedChannel{}, eris.Errorf("unsupported channel type %q", request.Type)
	}
	if !credentials.permissions.allowSession {
		return AuthorizedChannel{}, eris.New("session channels are not permitted")
	}
	return AuthorizedChannel{
		channelType:        request.Type,
		credentialIdentity: credentials.identity(),
	}, nil
}

func (a *Authz) AuthorizeLaunch(
	ctx context.Context,
	credentials ConnectionCredentials,
	channel AuthorizedChannel,
	request LaunchRequest,
) (AuthorizedLaunchSpec, error) {
	if a == nil {
		return AuthorizedLaunchSpec{}, eris.New("server authorization is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AuthorizedLaunchSpec{}, err
	}
	if err := credentials.validate(); err != nil {
		return AuthorizedLaunchSpec{}, eris.Wrap(err, "validate connection credentials")
	}
	if channel.channelType != SessionChannelType || channel.credentialIdentity == nil || channel.credentialIdentity != credentials.identity() {
		return AuthorizedLaunchSpec{}, eris.New("authorized channel does not belong to these credentials")
	}

	permissions := credentials.permissions
	switch request.Kind {
	case LaunchShell:
		if !permissions.allowShell {
			return AuthorizedLaunchSpec{}, eris.New("shell launch is not permitted")
		}
		if strings.TrimSpace(request.Command) != "" {
			return AuthorizedLaunchSpec{}, eris.New("shell request must not contain a command")
		}
	case LaunchExec:
		if !permissions.allowExec {
			return AuthorizedLaunchSpec{}, eris.New("exec launch is not permitted")
		}
		if strings.TrimSpace(request.Command) == "" && permissions.forcedCommand == "" {
			return AuthorizedLaunchSpec{}, eris.New("exec command is required")
		}
	default:
		return AuthorizedLaunchSpec{}, eris.Errorf("unsupported launch kind %q", request.Kind)
	}

	var pty *PTYRequest
	if request.PTY != nil {
		if !permissions.allowPTY {
			return AuthorizedLaunchSpec{}, eris.New("PTY allocation is not permitted")
		}
		if request.PTY.Rows == 0 || request.PTY.Columns == 0 {
			return AuthorizedLaunchSpec{}, eris.New("PTY rows and columns must be greater than zero")
		}
		if strings.ContainsRune(request.PTY.Terminal, '\x00') {
			return AuthorizedLaunchSpec{}, eris.New("PTY terminal contains NUL")
		}
		copy := *request.PTY
		pty = &copy
	}

	environment, err := authorizeEnvironment(request.Environment, permissions.allowedEnvironment)
	if err != nil {
		return AuthorizedLaunchSpec{}, err
	}
	account := credentials.Account()
	if !filepath.IsAbs(account.HomeDir) {
		return AuthorizedLaunchSpec{}, eris.New("account home directory must be absolute")
	}
	if !filepath.IsAbs(account.LoginShell) {
		return AuthorizedLaunchSpec{}, eris.New("account login shell must be absolute")
	}

	kind := request.Kind
	command := strings.TrimSpace(request.Command)
	if strings.ContainsRune(command, '\x00') {
		return AuthorizedLaunchSpec{}, eris.New("command contains NUL")
	}
	if len(command) > 24<<10 {
		return AuthorizedLaunchSpec{}, eris.New("command exceeds maximum size")
	}
	if permissions.forcedCommand != "" {
		kind = LaunchExec
		command = permissions.forcedCommand
	}
	return AuthorizedLaunchSpec{
		kind:             kind,
		command:          command,
		executable:       account.LoginShell,
		workingDirectory: account.HomeDir,
		pty:              pty,
		environment:      environment,
		account:          usermodel.CloneAccount(account),
	}, nil
}

func authorizeEnvironment(requested map[string]string, allowedNames []string) (map[string]string, error) {
	if len(requested) > 128 {
		return nil, eris.New("too many environment variables")
	}
	allowed := make(map[string]struct{}, len(allowedNames))
	for _, name := range allowedNames {
		allowed[name] = struct{}{}
	}
	names := make([]string, 0, len(requested))
	for name := range requested {
		names = append(names, name)
	}
	slices.Sort(names)

	environment := make(map[string]string, len(requested))
	for _, name := range names {
		if err := validateEnvironmentName(name); err != nil {
			return nil, err
		}
		if _, ok := allowed[name]; !ok {
			return nil, eris.Errorf("environment variable %q is not permitted", name)
		}
		value := requested[name]
		if strings.ContainsRune(value, '\x00') {
			return nil, eris.Errorf("environment variable %q contains NUL", name)
		}
		if len(value) > 16<<10 {
			return nil, eris.Errorf("environment variable %q exceeds maximum size", name)
		}
		environment[name] = value
	}
	return environment, nil
}
