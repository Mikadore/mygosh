package services

import (
	"context"

	serverauthz "github.com/Mikadore/mygosh/app/server/authz"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/rotisserie/eris"
)

// Service is a channel-type implementation. It receives only immutable
// credentials and an already-authorized channel decision.
type Service interface {
	ChannelType() string
	Open(
		ctx context.Context,
		credentials serverauthz.ConnectionCredentials,
		authorized serverauthz.AuthorizedChannel,
		request session.ChannelOpenRequest,
	) (session.ChannelOpenDecision, error)
}

// Registry binds one immutable credential snapshot to the services available
// for that authenticated connection.
type Registry struct {
	credentials serverauthz.ConnectionCredentials
	authorizer  serverauthz.ChannelAuthorizer
	services    map[string]Service
}

func NewRegistry(
	credentials serverauthz.ConnectionCredentials,
	authorizer serverauthz.ChannelAuthorizer,
	registered ...Service,
) (*Registry, error) {
	if authorizer == nil {
		return nil, eris.New("channel authorizer is required")
	}
	services := make(map[string]Service, len(registered))
	for _, service := range registered {
		if service == nil {
			return nil, eris.New("registered service is required")
		}
		channelType := service.ChannelType()
		if channelType == "" {
			return nil, eris.New("registered service channel type is required")
		}
		if _, exists := services[channelType]; exists {
			return nil, eris.Errorf("duplicate service for channel type %q", channelType)
		}
		services[channelType] = service
	}
	return &Registry{
		credentials: credentials,
		authorizer:  authorizer,
		services:    services,
	}, nil
}

func (r *Registry) OnChannelOpen(ctx context.Context, request session.ChannelOpenRequest) session.ChannelOpenDecision {
	if r == nil {
		return rejected("unsupported-channel-open", "incoming channel opens are not supported")
	}
	service, ok := r.services[request.Type]
	if !ok {
		return rejected("unsupported-channel-type", "channel type is not supported")
	}
	authorized, err := r.authorizer.AuthorizeChannel(ctx, r.credentials, serverauthz.ChannelAuthorizationRequest{
		Type:    request.Type,
		Payload: append([]byte(nil), request.Payload...),
	})
	if err != nil {
		return rejected("channel-not-authorized", "channel is not authorized")
	}
	decision, err := service.Open(ctx, r.credentials, authorized, request)
	if err != nil {
		return rejected("channel-open-failed", "channel could not be opened")
	}
	return decision
}

func (r *Registry) OnGlobalRequest(_ context.Context, _ session.GlobalRequest) session.GlobalResponse {
	return session.GlobalResponse{
		Code:    "unsupported-global-request",
		Message: "global requests are not supported",
	}
}

func rejected(code string, message string) session.ChannelOpenDecision {
	return session.ChannelOpenDecision{Code: code, Message: message}
}
