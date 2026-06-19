package session

import (
	"context"
)

type Handler interface {
	OnChannelOpen(ctx context.Context, ch *Channel, req ChannelOpenRequest) ChannelOpenDecision
	OnGlobalRequest(ctx context.Context, req GlobalRequest) GlobalResponse
	OnDisconnect(ctx context.Context, err error)
}

type ChannelHandler interface {
	OnRequest(ctx context.Context, ch *Channel, req ChannelRequest) ChannelResponse
	OnEOF(ctx context.Context, ch *Channel)
	OnClose(ctx context.Context, ch *Channel)
}

// ChannelRequestReplyHandler is an optional extension for channel handlers
// that need to start work only after a requested reply has been written.
type ChannelRequestReplyHandler interface {
	OnRequestReplied(ctx context.Context, ch *Channel, req ChannelRequest, response ChannelResponse, sendErr error)
}

type ChannelOpenRequest struct {
	Type          string
	Payload       []byte
	InitialWindow uint32
	MaxPacketSize uint32
}

type ChannelOpenDecision struct {
	OK      bool
	Payload []byte
	Code    string
	Message string
	Handler ChannelHandler
}

type ChannelRequest struct {
	Type      string
	WantReply bool
	Payload   []byte
}

type ChannelResponse struct {
	OK      bool
	Payload []byte
	Code    string
	Message string
}

type GlobalRequest struct {
	Type      string
	WantReply bool
	Payload   []byte
}

type GlobalResponse struct {
	OK      bool
	Payload []byte
	Code    string
	Message string
}

type rejectAllHandler struct{}

type rejectAllChannelHandler struct{}

func normalizeHandler(handler Handler) Handler {
	if handler == nil {
		return rejectAllHandler{}
	}
	return handler
}

func normalizeChannelHandler(handler ChannelHandler) ChannelHandler {
	if handler == nil {
		return rejectAllChannelHandler{}
	}
	return handler
}

func (rejectAllHandler) OnChannelOpen(_ context.Context, _ *Channel, _ ChannelOpenRequest) ChannelOpenDecision {
	return ChannelOpenDecision{
		Code:    "unsupported-channel-open",
		Message: "incoming channel opens are not supported",
	}
}

func (rejectAllHandler) OnGlobalRequest(_ context.Context, _ GlobalRequest) GlobalResponse {
	return GlobalResponse{
		Code:    "unsupported-global-request",
		Message: "global requests are not supported",
	}
}

func (rejectAllHandler) OnDisconnect(_ context.Context, _ error) {}

func (rejectAllChannelHandler) OnRequest(_ context.Context, _ *Channel, _ ChannelRequest) ChannelResponse {
	return ChannelResponse{
		Code:    "unsupported-channel-request",
		Message: "channel requests are not supported",
	}
}

func (rejectAllChannelHandler) OnEOF(_ context.Context, _ *Channel)   {}
func (rejectAllChannelHandler) OnClose(_ context.Context, _ *Channel) {}
