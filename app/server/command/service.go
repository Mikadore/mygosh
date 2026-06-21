package command

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/Mikadore/mygosh/app/commandchannel"
	serverauthz "github.com/Mikadore/mygosh/app/server/authz"
	serverprocess "github.com/Mikadore/mygosh/app/server/process"
	commandprotocol "github.com/Mikadore/mygosh/lib/command"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/rotisserie/eris"
)

const trustedPath = "/usr/local/bin:/usr/bin:/bin"

type ProcessRunner interface {
	Start(ctx context.Context, spec serverprocess.Spec) (commandprotocol.RunningProcess, error)
}

type Service struct {
	authorizer serverauthz.LaunchAuthorizer
	runner     ProcessRunner
}

func NewService(authorizer serverauthz.LaunchAuthorizer, runner ProcessRunner) (*Service, error) {
	if authorizer == nil {
		return nil, eris.New("launch authorizer is required")
	}
	if runner == nil {
		return nil, eris.New("process runner is required")
	}
	return &Service{
		authorizer: authorizer,
		runner:     runner,
	}, nil
}

func (*Service) ChannelType() string {
	return commandprotocol.ChannelType
}

func (s *Service) Open(
	_ context.Context,
	credentials serverauthz.ConnectionCredentials,
	authorized serverauthz.AuthorizedChannel,
	request session.ChannelOpenRequest,
) (session.ChannelOpenDecision, error) {
	if s == nil {
		return session.ChannelOpenDecision{}, eris.New("command service is required")
	}
	if request.Type != commandprotocol.ChannelType {
		return session.ChannelOpenDecision{}, eris.Errorf("unsupported channel type %q", request.Type)
	}
	if len(request.Payload) != 0 {
		return session.ChannelOpenDecision{}, eris.New("command channel open payload must be empty")
	}
	return session.ChannelOpenDecision{
		OK: true,
		Handler: &channelHandler{
			service:     s,
			credentials: credentials,
			authorized:  authorized,
		},
	}, nil
}

type channelHandler struct {
	service     *Service
	credentials serverauthz.ConnectionCredentials
	authorized  serverauthz.AuthorizedChannel
}

func (h *channelHandler) OnOpen(_ context.Context, channel *session.Channel) {
	conn, err := commandchannel.New(channel)
	if err != nil {
		_ = channel.Close()
		return
	}
	go func() {
		starter := &authorizedStarter{
			service:     h.service,
			credentials: h.credentials,
			authorized:  h.authorized,
		}
		if err := commandprotocol.Serve(conn, starter); err != nil {
			slog.Default().With("component", "command-service").Debug("command channel ended", "err", err)
		}
		_ = channel.Close()
	}()
}

func (*channelHandler) OnRequest(_ context.Context, _ *session.Channel, _ session.ChannelRequest) session.ChannelResponse {
	return session.ChannelResponse{
		Code:    "unsupported-channel-request",
		Message: "command channels do not use session requests",
	}
}

func (*channelHandler) OnEOF(_ context.Context, _ *session.Channel)   {}
func (*channelHandler) OnClose(_ context.Context, _ *session.Channel) {}

type authorizedStarter struct {
	service     *Service
	credentials serverauthz.ConnectionCredentials
	authorized  serverauthz.AuthorizedChannel
}

func (s *authorizedStarter) Start(ctx context.Context, request commandprotocol.StartRequest) (commandprotocol.RunningProcess, error) {
	launchRequest, err := toLaunchRequest(request)
	if err != nil {
		return nil, err
	}
	authorized, err := s.service.authorizer.AuthorizeLaunch(
		ctx,
		s.credentials,
		s.authorized,
		launchRequest,
	)
	if err != nil {
		return nil, eris.Wrap(err, "authorize command launch")
	}
	spec, err := toProcessSpec(authorized)
	if err != nil {
		return nil, err
	}
	return s.service.runner.Start(ctx, spec)
}

func toLaunchRequest(request commandprotocol.StartRequest) (serverauthz.LaunchRequest, error) {
	launch := serverauthz.LaunchRequest{
		Command:     request.Command,
		Environment: cloneEnvironment(request.Environment),
	}
	switch request.Kind {
	case commandprotocol.StartShell:
		launch.Kind = serverauthz.LaunchShell
	case commandprotocol.StartExec:
		launch.Kind = serverauthz.LaunchExec
	default:
		return serverauthz.LaunchRequest{}, eris.Errorf("unsupported command start kind %d", request.Kind)
	}
	if request.PTY != nil {
		launch.PTY = &serverauthz.PTYRequest{
			Terminal: request.PTY.Terminal,
			Rows:     request.PTY.Rows,
			Columns:  request.PTY.Columns,
		}
		if request.PTY.Terminal != "" {
			if existing, exists := launch.Environment["TERM"]; exists && existing != request.PTY.Terminal {
				return serverauthz.LaunchRequest{}, eris.New("PTY terminal conflicts with requested TERM")
			}
			launch.Environment["TERM"] = request.PTY.Terminal
		}
	}
	return launch, nil
}

func toProcessSpec(launch serverauthz.AuthorizedLaunchSpec) (serverprocess.Spec, error) {
	account := launch.Account()
	shell := launch.Executable()
	argv0 := filepath.Base(shell)
	var argv []string
	switch launch.Kind() {
	case serverauthz.LaunchShell:
		argv = []string{"-" + argv0}
	case serverauthz.LaunchExec:
		argv = []string{argv0, "-c", launch.Command()}
	default:
		return serverprocess.Spec{}, eris.Errorf("unsupported authorized launch kind %q", launch.Kind())
	}
	groups := make([]uint32, 0, len(account.SupplementaryGroups))
	for _, group := range account.SupplementaryGroups {
		groups = append(groups, group.Id)
	}
	spec := serverprocess.Spec{
		Executable:       shell,
		Argv:             argv,
		WorkingDirectory: launch.WorkingDirectory(),
		TrustedEnvironment: map[string]string{
			"HOME":    account.HomeDir,
			"USER":    account.Username,
			"LOGNAME": account.Username,
			"SHELL":   shell,
			"PATH":    trustedPath,
		},
		RequestedEnvironment: launch.Environment(),
		UID:                  account.Id,
		GID:                  account.PrimaryGroup.Id,
		SupplementaryGroups:  groups,
	}
	if requestedPTY := launch.PTY(); requestedPTY != nil {
		spec.PTY = &serverprocess.PTYSpec{
			Terminal: requestedPTY.Terminal,
			Rows:     requestedPTY.Rows,
			Columns:  requestedPTY.Columns,
		}
	}
	return spec, nil
}

func cloneEnvironment(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for name, value := range source {
		copy[name] = value
	}
	return copy
}
