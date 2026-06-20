package session

import (
	"context"
	"io"
	"math"
	"sync"
	"time"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/rotisserie/eris"
	"google.golang.org/protobuf/proto"
)

var (
	errSessionNotActive = eris.New("session not active")
	errSessionClosed    = eris.New("session closed")
	errChannelClosed    = eris.New("channel closed")
	errChannelWriteEOF  = eris.New("channel write side closed")
	errResourceLimit    = eris.New("session resource limit reached")
)

type channelState uint8

const (
	channelOpening channelState = iota
	channelOpen
	channelLocalEOF
	channelRemoteEOF
	channelBothEOF
	channelClosing
	channelClosed
	channelFailed
)

func (s channelState) String() string {
	switch s {
	case channelOpening:
		return "opening"
	case channelOpen:
		return "open"
	case channelLocalEOF:
		return "local-eof"
	case channelRemoteEOF:
		return "remote-eof"
	case channelBothEOF:
		return "both-eof"
	case channelClosing:
		return "closing"
	case channelClosed:
		return "closed"
	case channelFailed:
		return "failed"
	default:
		return "unknown"
	}
}

func (s channelState) allowsRequests() bool {
	switch s {
	case channelOpen, channelLocalEOF, channelRemoteEOF, channelBothEOF:
		return true
	default:
		return false
	}
}

func (s channelState) canSendData() bool {
	return s == channelOpen || s == channelRemoteEOF
}

func (s channelState) canReceiveData() bool {
	return s == channelOpen || s == channelLocalEOF
}

func (s channelState) readEOF() bool {
	switch s {
	case channelRemoteEOF, channelBothEOF, channelClosing, channelClosed:
		return true
	default:
		return false
	}
}

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
	size    uint64
}

type Channel struct {
	sess *Session

	id     uint64
	peerID uint64
	typ    string
	slot   channelSlot

	ctx    context.Context
	cancel context.CancelCauseFunc

	mu sync.Mutex

	state    channelState
	openWait chan error

	localWindow        uint32
	remoteWindow       uint32
	maxLocalPacket     uint32
	maxRemotePacket    uint32
	pendingWindowBytes uint32

	nextRequestID      uint64
	pendingRequests    map[uint64]chan channelWaitResult
	incomingRequestIDs map[uint64]struct{}

	frames [][]byte

	queuedFrames uint32
	queuedBytes  uint64
	sessionErr   error
	handler      ChannelHandler
	stateCh      chan struct{}
	events       chan channelEvent
}

func newPendingChannel(sess *Session, localID uint64, typ string, handler ChannelHandler) *Channel {
	ctx, cancel := context.WithCancelCause(sess.Context())
	return &Channel{
		sess:               sess,
		id:                 localID,
		typ:                typ,
		ctx:                ctx,
		cancel:             cancel,
		state:              channelOpening,
		openWait:           make(chan error, 1),
		pendingRequests:    make(map[uint64]chan channelWaitResult),
		incomingRequestIDs: make(map[uint64]struct{}),
		handler:            normalizeChannelHandler(handler),
		stateCh:            make(chan struct{}),
		events:             make(chan channelEvent, int(sess.config.Limits.MaxQueuedFramesPerChannel)),
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
		state:              channelOpening,
		localWindow:        sess.config.InitialWindow,
		remoteWindow:       remoteWindow,
		maxLocalPacket:     sess.config.MaxPacketSize,
		maxRemotePacket:    maxRemotePacket,
		pendingRequests:    make(map[uint64]chan channelWaitResult),
		incomingRequestIDs: make(map[uint64]struct{}),
		handler:            normalizeChannelHandler(handler),
		stateCh:            make(chan struct{}),
		events:             make(chan channelEvent, int(sess.config.Limits.MaxQueuedFramesPerChannel)),
	}
}

func (ch *Channel) Context() context.Context {
	if ch == nil || ch.ctx == nil {
		return context.Background()
	}
	return ch.ctx
}

func (ch *Channel) Type() string {
	if ch == nil {
		return ""
	}
	return ch.typ
}

// MaxSendFrameSize reports the largest channel-data frame the peer advertised.
// Higher-level protocols should use it to chunk their own encoded frames.
func (ch *Channel) MaxSendFrameSize() int {
	if ch == nil {
		return 0
	}
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return int(ch.maxRemotePacket)
}

func (ch *Channel) Send(ctx context.Context, frame []byte) error {
	ctx = normalizeContext(ctx)
	frame = cloneBytes(frame)
	if len(frame) == 0 {
		return eris.New("empty channel data is not allowed")
	}
	if len(frame) > math.MaxUint32 {
		return eris.Errorf("channel frame is too large: %d bytes", len(frame))
	}

	for {
		ch.mu.Lock()
		if err := ch.channelErrorLocked(); err != nil {
			ch.mu.Unlock()
			return err
		}
		if !ch.state.canSendData() {
			state := ch.state
			ch.mu.Unlock()
			if state == channelLocalEOF || state == channelBothEOF {
				return errChannelWriteEOF
			}
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

			err := ch.sess.sendEnvelope(ctx, &sessionpb.Envelope{
				Kind: &sessionpb.Envelope_ChannelData{
					ChannelData: &sessionpb.ChannelData{
						RecipientChannelId: peerID,
						Data:               frame,
					},
				},
			})
			if err != nil {
				ch.mu.Lock()
				if math.MaxUint32-ch.remoteWindow >= uint32(len(frame)) {
					ch.remoteWindow += uint32(len(frame))
					ch.signalLocked()
				}
				ch.mu.Unlock()
			}
			return err
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
			ch.releaseQueuedLocked(1, uint64(len(frame)))

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

		if ch.state.readEOF() {
			closed := ch.state == channelClosed
			ch.mu.Unlock()
			if closed {
				ch.cancel(errChannelClosed)
			}
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
				if eris.Is(err, errSessionClosed) || eris.Is(err, errChannelClosed) {
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
	if err := ch.sess.validateTypeAndPayload(typ, payload); err != nil {
		return nil, err
	}

	ch.mu.Lock()
	if err := ch.channelErrorLocked(); err != nil {
		ch.mu.Unlock()
		return nil, err
	}
	if !ch.state.allowsRequests() {
		ch.mu.Unlock()
		return nil, errChannelClosed
	}
	if ch.nextRequestID == math.MaxUint64 {
		ch.mu.Unlock()
		return nil, eris.New("channel request id space exhausted")
	}
	requestID := ch.nextRequestID
	ch.nextRequestID++

	var waitCh chan channelWaitResult
	if wantReply {
		if uint32(len(ch.pendingRequests)) >= ch.sess.config.Limits.MaxPendingChannelRequestsPerChannel {
			ch.mu.Unlock()
			return nil, eris.New("per-channel pending request limit reached")
		}
		if err := ch.sess.reservePendingChannelRequest(); err != nil {
			ch.mu.Unlock()
			return nil, err
		}
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
				Payload:            cloneBytes(payload),
			},
		},
	})
	if err != nil {
		if wantReply {
			ch.removePendingRequest(requestID, waitCh)
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
		ch.removePendingRequest(requestID, waitCh)
		return nil, ctx.Err()
	case <-ch.Context().Done():
		ch.removePendingRequest(requestID, waitCh)
		return nil, ch.channelError()
	}
}

func (ch *Channel) CloseWrite() error {
	ch.mu.Lock()
	if err := ch.channelErrorLocked(); err != nil {
		ch.mu.Unlock()
		return err
	}
	previous := ch.state
	switch ch.state {
	case channelOpen:
		ch.state = channelLocalEOF
	case channelRemoteEOF:
		ch.state = channelBothEOF
	case channelLocalEOF, channelBothEOF:
		ch.mu.Unlock()
		return nil
	default:
		ch.mu.Unlock()
		return errChannelClosed
	}
	peerID := ch.peerID
	ch.signalLocked()
	ch.mu.Unlock()

	err := ch.sess.sendEnvelope(context.Background(), &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelEof{
			ChannelEof: &sessionpb.ChannelEof{RecipientChannelId: peerID},
		},
	})
	if err != nil {
		ch.mu.Lock()
		if ch.state == channelLocalEOF || ch.state == channelBothEOF {
			ch.state = previous
			ch.signalLocked()
		}
		ch.mu.Unlock()
	}
	return err
}

func (ch *Channel) Close() error {
	if ch == nil {
		return nil
	}

	ch.mu.Lock()
	switch ch.state {
	case channelClosing, channelClosed, channelFailed:
		ch.mu.Unlock()
		return nil
	case channelOpening:
		ch.state = channelFailed
		ch.signalLocked()
		ch.mu.Unlock()
		ch.sess.removeChannel(ch.id)
		ch.shutdown(errChannelClosed)
		return nil
	default:
		ch.state = channelClosing
	}
	ch.discardQueuedLocked()
	ch.failPendingRequestsLocked(errChannelClosed)
	peerID := ch.peerID
	ch.signalLocked()
	ch.cancel(errChannelClosed)
	ch.mu.Unlock()

	err := ch.sess.sendEnvelopeAsync(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelClose{
			ChannelClose: &sessionpb.ChannelClose{RecipientChannelId: peerID},
		},
	}, true)
	if err != nil {
		ch.sess.shutdown(eris.Wrap(err, "enqueue channel close"))
		return err
	}

	go ch.awaitCloseTimeout()
	return nil
}

func (ch *Channel) awaitCloseTimeout() {
	timer := time.NewTimer(ch.sess.config.ChannelCloseTimeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		ch.mu.Lock()
		if ch.state != channelClosing {
			ch.mu.Unlock()
			return
		}
		ch.state = channelClosed
		ch.signalLocked()
		ch.mu.Unlock()
		ch.sess.removeChannel(ch.id)
	case <-ch.sess.Context().Done():
	}
}

func (s *Session) enqueueChannelRequest(msg *sessionpb.ChannelRequest) error {
	if msg == nil {
		return s.protocolErrorf("received nil channel request")
	}
	if err := s.validateTypeAndPayload(msg.GetRequestType(), msg.GetPayload()); err != nil {
		return s.protocolErrorf("invalid channel request: %v", err)
	}
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel request for unknown channel %d", msg.GetRecipientChannelId())
	}

	event := channelEvent{kind: channelEventRequest, request: msg, size: uint64(proto.Size(msg))}
	ch.mu.Lock()
	if !ch.state.allowsRequests() {
		state := ch.state
		ch.mu.Unlock()
		return s.protocolErrorf("received channel request while channel %d is %s", ch.id, state)
	}
	if msg.GetWantReply() {
		if _, exists := ch.incomingRequestIDs[msg.GetRequestId()]; exists {
			ch.mu.Unlock()
			return s.protocolErrorf("received duplicate request id %d on channel %d", msg.GetRequestId(), ch.id)
		}
		ch.incomingRequestIDs[msg.GetRequestId()] = struct{}{}
	}
	if err := ch.reserveQueuedLocked(1, event.size); err != nil {
		peerID := ch.peerID
		ch.mu.Unlock()
		if eris.Is(err, errResourceLimit) && msg.GetWantReply() {
			sendErr := s.sendChannelRejectAsync(
				peerID,
				msg.GetRequestId(),
				"resource-limit",
				"channel request queue limit reached",
				func(error) {
					ch.finishIncomingRequest(msg.GetRequestId(), true)
				},
			)
			if sendErr != nil {
				ch.finishIncomingRequest(msg.GetRequestId(), true)
			}
			return sendErr
		}
		ch.finishIncomingRequest(msg.GetRequestId(), msg.GetWantReply())
		return err
	}
	select {
	case ch.events <- event:
		ch.mu.Unlock()
		return nil
	default:
		ch.releaseQueuedLocked(1, event.size)
		peerID := ch.peerID
		ch.mu.Unlock()
		if msg.GetWantReply() {
			sendErr := s.sendChannelRejectAsync(
				peerID,
				msg.GetRequestId(),
				"resource-limit",
				"channel request queue limit reached",
				func(error) {
					ch.finishIncomingRequest(msg.GetRequestId(), true)
				},
			)
			if sendErr != nil {
				ch.finishIncomingRequest(msg.GetRequestId(), true)
			}
			return sendErr
		}
		return errResourceLimit
	}
}

func (s *Session) enqueueChannelEOF(localID uint64) error {
	ch := s.lookupChannel(localID)
	if ch == nil {
		return s.protocolErrorf("received channel EOF for unknown channel %d", localID)
	}
	event := channelEvent{kind: channelEventEOF, size: 1}

	ch.mu.Lock()
	switch ch.state {
	case channelOpen:
		ch.state = channelRemoteEOF
	case channelLocalEOF:
		ch.state = channelBothEOF
	case channelRemoteEOF, channelBothEOF:
		ch.mu.Unlock()
		return s.protocolErrorf("received duplicate channel EOF for channel %d", localID)
	default:
		state := ch.state
		ch.mu.Unlock()
		return s.protocolErrorf("received channel EOF while channel %d is %s", localID, state)
	}
	ch.signalLocked()
	if err := ch.reserveQueuedLocked(1, event.size); err != nil {
		ch.mu.Unlock()
		return err
	}
	select {
	case ch.events <- event:
		ch.mu.Unlock()
		return nil
	default:
		ch.releaseQueuedLocked(1, event.size)
		ch.mu.Unlock()
		return errResourceLimit
	}
}

func (s *Session) enqueueChannelClose(localID uint64) error {
	ch := s.lookupChannel(localID)
	if ch == nil {
		return s.protocolErrorf("received channel close for unknown channel %d", localID)
	}

	ch.mu.Lock()
	if ch.state == channelClosing {
		ch.state = channelClosed
		ch.signalLocked()
		ch.mu.Unlock()
		s.removeChannel(ch.id)
		return nil
	}
	switch ch.state {
	case channelOpen, channelLocalEOF, channelRemoteEOF, channelBothEOF:
		ch.state = channelClosed
	case channelOpening:
		ch.mu.Unlock()
		return s.protocolErrorf("received channel close before channel %d was opened", localID)
	default:
		state := ch.state
		ch.mu.Unlock()
		return s.protocolErrorf("received duplicate channel close while channel %d is %s", localID, state)
	}
	ch.signalLocked()
	peerID := ch.peerID
	event := channelEvent{kind: channelEventClose, size: 1}
	if err := ch.reserveQueuedLocked(1, event.size); err != nil {
		ch.mu.Unlock()
		return err
	}
	select {
	case ch.events <- event:
		ch.mu.Unlock()
		if err := s.sendEnvelopeAsync(&sessionpb.Envelope{
			Kind: &sessionpb.Envelope_ChannelClose{
				ChannelClose: &sessionpb.ChannelClose{RecipientChannelId: peerID},
			},
		}, true); err != nil {
			return eris.Wrap(err, "enqueue channel close acknowledgement")
		}
		s.removeChannel(ch.id)
		return nil
	default:
		ch.releaseQueuedLocked(1, event.size)
		ch.mu.Unlock()
		return errResourceLimit
	}
}

func (s *Session) sendChannelRejectAsync(
	peerID uint64,
	requestID uint64,
	code string,
	message string,
	after func(error),
) error {
	return s.sendEnvelopeAsyncAfter(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelResult{
			ChannelResult: &sessionpb.ChannelResult{
				RecipientChannelId: peerID,
				RequestId:          requestID,
				Result: &sessionpb.ChannelResult_Reject{
					Reject: &sessionpb.OperationReject{Code: code, Message: message},
				},
			},
		},
	}, true, after)
}

func (ch *Channel) loop() {
	defer ch.sess.wg.Done()
	if !ch.sess.waitForActivation() {
		return
	}
	select {
	case <-ch.Context().Done():
		return
	default:
	}

	ch.mu.Lock()
	handler := ch.handler
	ch.mu.Unlock()
	handler.OnOpen(ch.Context(), ch)

	for {
		select {
		case event := <-ch.events:
			ch.mu.Lock()
			ch.releaseQueuedLocked(1, event.size)
			ch.mu.Unlock()
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
		ch.mu.Lock()
		handler := ch.handler
		ch.mu.Unlock()
		handler.OnEOF(ch.Context(), ch)
		return nil
	case channelEventClose:
		return ch.handleRemoteClose()
	default:
		return eris.Errorf("unsupported channel event %d", event.kind)
	}
}

func (ch *Channel) handleRequest(msg *sessionpb.ChannelRequest) error {
	defer ch.finishIncomingRequest(msg.GetRequestId(), msg.GetWantReply())

	ch.mu.Lock()
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
	if err := ch.sess.validateResponse(response.Code, response.Message, response.Payload); err != nil {
		return err
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

func (ch *Channel) handleRemoteClose() error {
	ch.mu.Lock()
	handler := ch.handler
	ch.failPendingRequestsLocked(errChannelClosed)
	cancelNow := len(ch.frames) == 0
	ch.mu.Unlock()

	handler.OnClose(ch.Context(), ch)
	if cancelNow {
		ch.cancel(errChannelClosed)
	}
	return nil
}

func (ch *Channel) finishIncomingRequest(requestID uint64, wantReply bool) {
	if !wantReply {
		return
	}
	ch.mu.Lock()
	delete(ch.incomingRequestIDs, requestID)
	ch.mu.Unlock()
}

func (ch *Channel) removePendingRequest(requestID uint64, waitCh chan channelWaitResult) {
	removed := false
	ch.mu.Lock()
	if current, ok := ch.pendingRequests[requestID]; ok && current == waitCh {
		delete(ch.pendingRequests, requestID)
		removed = true
	}
	ch.mu.Unlock()
	if removed {
		ch.sess.releasePendingChannelRequest()
	}
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

func (ch *Channel) reserveQueuedLocked(frames uint32, bytes uint64) error {
	if frames > ch.sess.config.Limits.MaxQueuedFramesPerChannel-ch.queuedFrames {
		return errResourceLimit
	}
	if bytes > ch.sess.config.Limits.MaxQueuedBytesPerChannel-ch.queuedBytes {
		return errResourceLimit
	}
	if err := ch.sess.reserveQueueBudget(frames, bytes); err != nil {
		return err
	}
	ch.queuedFrames += frames
	ch.queuedBytes += bytes
	return nil
}

func (ch *Channel) releaseQueuedLocked(frames uint32, bytes uint64) {
	actualFrames := frames
	if actualFrames > ch.queuedFrames {
		actualFrames = ch.queuedFrames
	}
	actualBytes := bytes
	if actualBytes > ch.queuedBytes {
		actualBytes = ch.queuedBytes
	}
	ch.queuedFrames -= actualFrames
	ch.queuedBytes -= actualBytes
	ch.sess.releaseQueueBudget(actualFrames, actualBytes)
}

func (ch *Channel) discardQueuedLocked() {
	frames := ch.queuedFrames
	bytes := ch.queuedBytes
	ch.queuedFrames = 0
	ch.queuedBytes = 0
	ch.frames = nil
	ch.sess.releaseQueueBudget(frames, bytes)
}

func (ch *Channel) failPendingRequestsLocked(err error) {
	count := uint32(0)
	for _, waitCh := range ch.pendingRequests {
		count++
		select {
		case waitCh <- channelWaitResult{err: err}:
		default:
		}
	}
	ch.pendingRequests = make(map[uint64]chan channelWaitResult)
	for range count {
		ch.sess.releasePendingChannelRequest()
	}
}

func (ch *Channel) shutdown(err error) {
	if err == nil {
		err = errSessionClosed
	}

	ch.mu.Lock()
	if ch.sessionErr == nil {
		ch.sessionErr = err
	}
	if ch.state != channelClosed {
		ch.state = channelFailed
	}
	ch.discardQueuedLocked()
	ch.failPendingRequestsLocked(err)
	if ch.openWait != nil {
		select {
		case ch.openWait <- err:
		default:
		}
		ch.openWait = nil
	}
	ch.signalLocked()
	ch.cancel(err)
	ch.mu.Unlock()
}
