package session

import (
	"context"
	"io"
	"math"
	"sync"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/rotisserie/eris"
)

var (
	errSessionNotActive = eris.New("session not active")
	errSessionClosed    = eris.New("session closed")
	errChannelClosed    = eris.New("channel closed")
	errChannelWriteEOF  = eris.New("channel write side closed")
)

type channelWaitResult struct {
	response *ChannelResponse
	err      error
}

type channelEventKind uint8

const (
	channelEventRequest channelEventKind = iota
	channelEventEOF
	channelEventClose
)

type channelEvent struct {
	kind    channelEventKind
	request *sessionpb.ChannelRequest
}

type Channel struct {
	sess *Session

	id     uint64
	peerID uint64
	typ    string

	ctx    context.Context
	cancel context.CancelCauseFunc

	mu sync.Mutex

	openConfirmed bool
	openCanceled  bool
	openWait      chan error

	localWindow        uint32
	remoteWindow       uint32
	maxLocalPacket     uint32
	maxRemotePacket    uint32
	pendingWindowBytes uint32

	nextRequestID   uint64
	pendingRequests map[uint64]chan channelWaitResult

	frames [][]byte

	eofReceived   bool
	eofSent       bool
	closeReceived bool
	closeSent     bool
	localClosed   bool

	sessionErr error
	handler    ChannelHandler
	stateCh    chan struct{}
	events     chan channelEvent
}

func newPendingChannel(sess *Session, localID uint64, typ string, handler ChannelHandler) *Channel {
	ctx, cancel := context.WithCancelCause(sess.Context())
	return &Channel{
		sess:            sess,
		id:              localID,
		typ:             typ,
		ctx:             ctx,
		cancel:          cancel,
		openWait:        make(chan error, 1),
		pendingRequests: make(map[uint64]chan channelWaitResult),
		handler:         normalizeChannelHandler(handler),
		stateCh:         make(chan struct{}),
		events:          make(chan channelEvent, sess.config.HandlerQueueDepth),
	}
}

func newIncomingChannel(sess *Session, localID uint64, peerID uint64, typ string, remoteWindow uint32, maxRemotePacket uint32, handler ChannelHandler) *Channel {
	ctx, cancel := context.WithCancelCause(sess.Context())
	return &Channel{
		sess:               sess,
		id:                 localID,
		peerID:             peerID,
		typ:                typ,
		ctx:                ctx,
		cancel:             cancel,
		openConfirmed:      true,
		localWindow:        sess.config.InitialWindow,
		remoteWindow:       remoteWindow,
		maxLocalPacket:     sess.config.MaxPacketSize,
		maxRemotePacket:    maxRemotePacket,
		pendingRequests:    make(map[uint64]chan channelWaitResult),
		handler:            normalizeChannelHandler(handler),
		stateCh:            make(chan struct{}),
		events:             make(chan channelEvent, sess.config.HandlerQueueDepth),
		pendingWindowBytes: 0,
	}
}

func (ch *Channel) Context() context.Context {
	if ch == nil || ch.ctx == nil {
		return context.Background()
	}
	return ch.ctx
}

func (ch *Channel) Type() string {
	return ch.typ
}

func (ch *Channel) Send(ctx context.Context, frame []byte) error {
	ctx = normalizeContext(ctx)
	frame = cloneBytes(frame)

	if len(frame) > math.MaxUint32 {
		return eris.Errorf("channel frame is too large: %d bytes", len(frame))
	}

	for {
		ch.mu.Lock()
		if err := ch.channelErrorLocked(); err != nil {
			ch.mu.Unlock()
			return err
		}
		if !ch.openConfirmed {
			ch.mu.Unlock()
			return eris.New("channel is not open")
		}
		if ch.eofSent {
			ch.mu.Unlock()
			return errChannelWriteEOF
		}
		if ch.closeSent || ch.closeReceived {
			ch.mu.Unlock()
			return errChannelClosed
		}
		if len(frame) > int(ch.maxRemotePacket) {
			maxRemotePacket := ch.maxRemotePacket
			ch.mu.Unlock()
			return eris.Errorf("channel frame exceeds remote max packet size: %d > %d", len(frame), maxRemotePacket)
		}
		if uint32(len(frame)) <= ch.remoteWindow {
			ch.remoteWindow -= uint32(len(frame))
			peerID := ch.peerID
			ch.mu.Unlock()

			return ch.sess.sendEnvelope(ctx, &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_ChannelData{
					ChannelData: &sessionpb.ChannelData{
						RecipientChannelId: peerID,
						Data:               frame,
					},
				},
			})
		}

		waitCh := ch.stateCh
		ch.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch.Context().Done():
			if err := ch.channelError(); err != nil {
				return err
			}
			return errChannelClosed
		case <-waitCh:
		}
	}
}

func (ch *Channel) Recv(ctx context.Context) ([]byte, error) {
	ctx = normalizeContext(ctx)

	for {
		ch.mu.Lock()
		if len(ch.frames) > 0 {
			frame := cloneBytes(ch.frames[0])
			ch.frames[0] = nil
			ch.frames = ch.frames[1:]

			size := uint32(len(frame))
			ch.localWindow += size
			ch.pendingWindowBytes += size

			var adjust uint32
			if ch.pendingWindowBytes >= ch.sess.config.WindowAdjustThreshold {
				adjust = ch.pendingWindowBytes
				ch.pendingWindowBytes = 0
			}

			peerID := ch.peerID
			ch.mu.Unlock()

			if adjust > 0 {
				if err := ch.sess.sendEnvelope(context.Background(), &sessionpb.Envelope{
					Kind: &sessionpb.Envelope_ChannelWindowAdjust{
						ChannelWindowAdjust: &sessionpb.ChannelWindowAdjust{
							RecipientChannelId: peerID,
							BytesToAdd:         adjust,
						},
					},
				}); err != nil {
					ch.sess.shutdown(eris.Wrap(err, "send channel window adjust"))
				}
			}

			return frame, nil
		}

		if ch.localClosed || ch.closeReceived || ch.eofReceived {
			ch.mu.Unlock()
			return nil, io.EOF
		}
		if ch.sessionErr != nil {
			err := ch.sessionErr
			ch.mu.Unlock()
			if eris.Is(err, errSessionClosed) {
				return nil, io.EOF
			}
			return nil, err
		}

		waitCh := ch.stateCh
		ch.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ch.Context().Done():
			if err := ch.channelError(); err != nil {
				if eris.Is(err, errSessionClosed) {
					return nil, io.EOF
				}
				return nil, err
			}
			return nil, io.EOF
		case <-waitCh:
		}
	}
}

func (ch *Channel) SendRequest(ctx context.Context, typ string, payload []byte, wantReply bool) (*ChannelResponse, error) {
	ctx = normalizeContext(ctx)
	if typ == "" {
		return nil, eris.New("channel request type is required")
	}

	payload = cloneBytes(payload)

	ch.mu.Lock()
	if err := ch.channelErrorLocked(); err != nil {
		ch.mu.Unlock()
		return nil, err
	}
	if !ch.openConfirmed {
		ch.mu.Unlock()
		return nil, eris.New("channel is not open")
	}
	if ch.closeSent || ch.closeReceived {
		ch.mu.Unlock()
		return nil, errChannelClosed
	}

	requestID := ch.nextRequestID
	ch.nextRequestID++

	var waitCh chan channelWaitResult
	if wantReply {
		waitCh = make(chan channelWaitResult, 1)
		ch.pendingRequests[requestID] = waitCh
	}

	peerID := ch.peerID
	ch.mu.Unlock()

	err := ch.sess.sendEnvelope(ctx, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelRequest{
			ChannelRequest: &sessionpb.ChannelRequest{
				RecipientChannelId: peerID,
				RequestId:          requestID,
				RequestType:        typ,
				WantReply:          wantReply,
				Payload:            payload,
			},
		},
	})
	if err != nil {
		if wantReply {
			ch.mu.Lock()
			delete(ch.pendingRequests, requestID)
			ch.mu.Unlock()
		}
		return nil, err
	}
	if !wantReply {
		return nil, nil
	}

	select {
	case result := <-waitCh:
		return result.response, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ch.Context().Done():
		return nil, ch.channelError()
	}
}

func (ch *Channel) CloseWrite() error {
	ch.mu.Lock()
	if err := ch.channelErrorLocked(); err != nil {
		ch.mu.Unlock()
		return err
	}
	if !ch.openConfirmed {
		ch.mu.Unlock()
		return eris.New("channel is not open")
	}
	if ch.closeSent || ch.closeReceived {
		ch.mu.Unlock()
		return errChannelClosed
	}
	if ch.eofSent {
		ch.mu.Unlock()
		return nil
	}

	ch.eofSent = true
	peerID := ch.peerID
	ch.signalLocked()
	ch.mu.Unlock()

	return ch.sess.sendEnvelope(context.Background(), &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelEof{
			ChannelEof: &sessionpb.ChannelEof{RecipientChannelId: peerID},
		},
	})
}

func (ch *Channel) Close() error {
	ch.mu.Lock()
	if ch.closeSent {
		ch.localClosed = true
		ch.frames = nil
		ch.signalLocked()
		shouldRemove := ch.closeReceived
		ch.cancel(errChannelClosed)
		ch.mu.Unlock()
		if shouldRemove {
			ch.sess.removeChannel(ch.id)
		}
		return nil
	}

	ch.closeSent = true
	ch.localClosed = true
	ch.frames = nil
	ch.signalLocked()
	ch.failPendingRequestsLocked(errChannelClosed)
	peerID := ch.peerID
	openConfirmed := ch.openConfirmed
	shouldRemove := ch.closeReceived
	ch.cancel(errChannelClosed)
	ch.mu.Unlock()

	if shouldRemove {
		defer ch.sess.removeChannel(ch.id)
	}
	if !openConfirmed {
		return nil
	}

	return ch.sess.sendEnvelope(context.Background(), &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelClose{
			ChannelClose: &sessionpb.ChannelClose{RecipientChannelId: peerID},
		},
	})
}

func (ch *Channel) enqueueEvent(event channelEvent) error {
	select {
	case ch.events <- event:
		return nil
	default:
		return ch.sess.queueExhausted("channel handler queue exhausted")
	}
}

func (ch *Channel) loop() {
	defer ch.sess.wg.Done()

	if !ch.sess.waitForActivation() {
		return
	}

	for {
		select {
		case event := <-ch.events:
			if err := ch.handleEvent(event); err != nil {
				ch.sess.shutdown(err)
				return
			}
		case <-ch.Context().Done():
			return
		}
	}
}

func (ch *Channel) handleEvent(event channelEvent) error {
	switch event.kind {
	case channelEventRequest:
		return ch.handleRequest(event.request)
	case channelEventEOF:
		return ch.handleEOF()
	case channelEventClose:
		return ch.handleClose()
	default:
		return eris.Errorf("unsupported channel event %d", event.kind)
	}
}

func (ch *Channel) handleRequest(msg *sessionpb.ChannelRequest) error {
	ch.mu.Lock()
	if !ch.openConfirmed {
		ch.mu.Unlock()
		return ch.sess.protocolErrorf("received channel request before channel %d was opened", ch.id)
	}
	if ch.closeSent || ch.closeReceived {
		ch.mu.Unlock()
		return ch.sess.protocolErrorf("received channel request for closed channel %d", ch.id)
	}
	handler := ch.handler
	peerID := ch.peerID
	ch.mu.Unlock()

	response := handler.OnRequest(ch.Context(), ch, ChannelRequest{
		Type:      msg.GetRequestType(),
		WantReply: msg.GetWantReply(),
		Payload:   cloneBytes(msg.GetPayload()),
	})

	if !msg.GetWantReply() {
		return nil
	}

	result := &sessionpb.ChannelResult{
		RecipientChannelId: peerID,
		RequestId:          msg.GetRequestId(),
	}
	if response.OK {
		result.Result = &sessionpb.ChannelResult_Success{
			Success: &sessionpb.OperationSuccess{Payload: cloneBytes(response.Payload)},
		}
	} else {
		result.Result = &sessionpb.ChannelResult_Reject{
			Reject: &sessionpb.OperationReject{
				Code:    normalizeRejectCode(response.Code, "channel-request-rejected"),
				Message: normalizeRejectMessage(response.Message, "channel request rejected"),
				Payload: cloneBytes(response.Payload),
			},
		}
	}

	return ch.sess.sendEnvelope(ch.Context(), &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelResult{ChannelResult: result},
	})
}

func (ch *Channel) handleEOF() error {
	ch.mu.Lock()
	if ch.closeSent || ch.closeReceived {
		ch.mu.Unlock()
		return ch.sess.protocolErrorf("received channel EOF after channel %d was closed", ch.id)
	}
	if ch.eofReceived {
		ch.mu.Unlock()
		return nil
	}
	ch.eofReceived = true
	ch.signalLocked()
	handler := ch.handler
	ch.mu.Unlock()

	handler.OnEOF(ch.Context(), ch)
	return nil
}

func (ch *Channel) handleClose() error {
	ch.mu.Lock()
	if ch.closeReceived {
		ch.mu.Unlock()
		return nil
	}
	ch.closeReceived = true
	ch.localClosed = true
	ch.frames = nil
	ch.signalLocked()
	handler := ch.handler
	shouldRemove := ch.closeSent
	ch.failPendingRequestsLocked(errChannelClosed)
	ch.cancel(errChannelClosed)
	ch.mu.Unlock()

	handler.OnClose(ch.Context(), ch)
	if shouldRemove {
		ch.sess.removeChannel(ch.id)
	}
	return nil
}

func (ch *Channel) channelError() error {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.channelErrorLocked()
}

func (ch *Channel) channelErrorLocked() error {
	if ch.sessionErr != nil {
		return ch.sessionErr
	}
	if ch.ctx != nil {
		if cause := context.Cause(ch.ctx); cause != nil {
			return cause
		}
	}
	return nil
}

func (ch *Channel) signalLocked() {
	close(ch.stateCh)
	ch.stateCh = make(chan struct{})
}

func (ch *Channel) failPendingRequestsLocked(err error) {
	for _, waitCh := range ch.pendingRequests {
		select {
		case waitCh <- channelWaitResult{err: err}:
		default:
		}
	}
	ch.pendingRequests = make(map[uint64]chan channelWaitResult)
}

func (ch *Channel) shutdown(err error) {
	if err == nil {
		err = errSessionClosed
	}

	ch.mu.Lock()
	if ch.sessionErr == nil {
		ch.sessionErr = err
	}
	ch.frames = nil
	ch.failPendingRequestsLocked(err)
	if ch.openWait != nil {
		select {
		case ch.openWait <- err:
		default:
		}
	}
	ch.signalLocked()
	ch.cancel(err)
	ch.mu.Unlock()
}
