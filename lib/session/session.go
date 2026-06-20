package session

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/rotisserie/eris"
)

type Options struct {
	Logger *slog.Logger
}

type Prepared struct {
	config  Config
	handler Handler
	logger  *slog.Logger
}

type globalWaitResult struct {
	response *GlobalResponse
	err      error
}

type outboundWrite struct {
	envelope *sessionpb.Envelope
	result   chan error
}

type dispatchTask interface {
	dispatch(*Session) error
}

type dispatchChannelOpen struct {
	message *sessionpb.ChannelOpen
}

type dispatchGlobalRequest struct {
	message *sessionpb.GlobalRequest
}

type protocolError struct {
	message string
}

func (e *protocolError) Error() string {
	return e.message
}

type Session struct {
	conn   wire.FramedConn
	logger *slog.Logger
	config Config

	ctx    context.Context
	cancel context.CancelCauseFunc

	mu                  sync.Mutex
	nextLocalChannelID  uint64
	channels            map[uint64]*Channel
	peerChannelIDs      map[uint64]uint64
	nextGlobalRequestID uint64
	pendingGlobal       map[uint64]chan globalWaitResult
	waitErr             error
	closeErr            error
	closing             bool

	queueMu       sync.Mutex
	queuesClosed  bool
	dispatchQueue chan dispatchTask
	controlQueue  chan outboundWrite
	outboundQueue chan outboundWrite

	activated  chan struct{}
	done       chan struct{}
	writerDone chan struct{}

	wg           sync.WaitGroup
	activateOnce sync.Once
	shutdownOnce sync.Once
	closeConn    sync.Once
	handler      Handler
}

func Prepare(cfg Config, handler Handler, opts Options) (*Prepared, error) {
	if err := cfg.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate session mux config")
	}

	return &Prepared{
		config:  cfg.withDefaults(),
		handler: normalizeHandler(handler),
		logger:  logging.Resolve(opts.Logger),
	}, nil
}

func (p *Prepared) Bind(parent context.Context, conn wire.FramedConn) (*Session, error) {
	if p == nil {
		return nil, eris.New("prepared session is required")
	}
	if conn == nil {
		return nil, eris.New("session connection is required")
	}

	parent = normalizeContext(parent)
	if err := parent.Err(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancelCause(parent)
	s := &Session{
		conn:          conn,
		logger:        logging.Resolve(p.logger),
		config:        p.config,
		ctx:           ctx,
		cancel:        cancel,
		channels:      make(map[uint64]*Channel),
		peerChannelIDs: make(map[uint64]uint64),
		pendingGlobal: make(map[uint64]chan globalWaitResult),
		dispatchQueue: make(chan dispatchTask, p.config.HandlerQueueDepth),
		controlQueue:  make(chan outboundWrite, 1),
		outboundQueue: make(chan outboundWrite, p.config.OutboundQueueDepth),
		activated:     make(chan struct{}),
		done:          make(chan struct{}),
		writerDone:    make(chan struct{}),
		handler:       p.handler,
	}

	s.wg.Add(3)
	go s.receiverLoop()
	go s.dispatchLoop()
	go s.writerLoop()

	return s, nil
}

func (s *Session) Activate() {
	if s == nil {
		return
	}
	s.activateOnce.Do(func() {
		close(s.activated)
	})
}

func (s *Session) Context() context.Context {
	if s == nil || s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

func (s *Session) Done() <-chan struct{} {
	if s == nil || s.done == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return s.done
}

func (s *Session) Wait() error {
	if s == nil {
		return eris.New("session is required")
	}
	<-s.Done()

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waitErr
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.shutdown(context.Canceled)
	return nil
}

func (s *Session) OpenChannel(ctx context.Context, typ string, payload []byte) (*Channel, error) {
	return s.OpenChannelWithHandler(ctx, typ, payload, nil)
}

func (s *Session) OpenChannelWithHandler(ctx context.Context, typ string, payload []byte, handler ChannelHandler) (*Channel, error) {
	ctx = normalizeContext(ctx)
	if typ == "" {
		return nil, eris.New("channel type is required")
	}
	if err := s.ensureActive(); err != nil {
		return nil, err
	}

	payload = cloneBytes(payload)

	s.mu.Lock()
	localID := s.nextLocalChannelID
	s.nextLocalChannelID++

	ch := newPendingChannel(s, localID, typ, handler)
	s.channels[localID] = ch
	waitCh := ch.openWait
	s.mu.Unlock()

	s.startChannelWorker(ch)

	err := s.sendEnvelope(ctx, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelOpen{
			ChannelOpen: &sessionpb.ChannelOpen{
				ChannelType:     typ,
				SenderChannelId: localID,
				InitialWindow:   s.config.InitialWindow,
				MaxPacketSize:   s.config.MaxPacketSize,
				Payload:         payload,
			},
		},
	})
	if err != nil {
		s.removeChannel(localID)
		ch.shutdown(err)
		return nil, err
	}

	select {
	case openErr := <-waitCh:
		if openErr != nil {
			return nil, openErr
		}
		return ch, nil
	case <-ctx.Done():
		ch.mu.Lock()
		ch.openCanceled = true
		ch.signalLocked()
		ch.mu.Unlock()
		return nil, ctx.Err()
	case <-s.Context().Done():
		return nil, s.closeCause()
	}
}

func (s *Session) SendGlobalRequest(ctx context.Context, typ string, payload []byte, wantReply bool) (*GlobalResponse, error) {
	ctx = normalizeContext(ctx)
	if typ == "" {
		return nil, eris.New("global request type is required")
	}
	if err := s.ensureActive(); err != nil {
		return nil, err
	}

	payload = cloneBytes(payload)

	s.mu.Lock()
	requestID := s.nextGlobalRequestID
	s.nextGlobalRequestID++

	var waitCh chan globalWaitResult
	if wantReply {
		waitCh = make(chan globalWaitResult, 1)
		s.pendingGlobal[requestID] = waitCh
	}
	s.mu.Unlock()

	err := s.sendEnvelope(ctx, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_GlobalRequest{
			GlobalRequest: &sessionpb.GlobalRequest{
				RequestId:   requestID,
				RequestType: typ,
				WantReply:   wantReply,
				Payload:     payload,
			},
		},
	})
	if err != nil {
		if wantReply {
			s.mu.Lock()
			delete(s.pendingGlobal, requestID)
			s.mu.Unlock()
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
	case <-s.Context().Done():
		return nil, s.closeCause()
	}
}

func (s *Session) receiverLoop() {
	defer s.wg.Done()

	if !s.waitForActivation() {
		return
	}

	for {
		var frame sessionpb.Envelope
		if err := wire.ReceiveProto(s.conn, &frame); err != nil {
			switch {
			case eris.Is(err, io.EOF):
				s.shutdown(nil)
			case context.Cause(s.Context()) != nil:
				s.shutdown(s.closeCause())
			default:
				s.shutdown(eris.Wrap(err, "receive session frame"))
			}
			return
		}

		if err := s.routeEnvelope(&frame); err != nil {
			s.shutdown(err)
			return
		}
	}
}

func (s *Session) dispatchLoop() {
	defer s.wg.Done()

	if !s.waitForActivation() {
		return
	}

	for {
		select {
		case task := <-s.dispatchQueue:
			if err := task.dispatch(s); err != nil {
				s.shutdown(err)
				return
			}
		case <-s.Context().Done():
			return
		}
	}
}

func (s *Session) writerLoop() {
	defer s.wg.Done()
	defer close(s.writerDone)

	if !s.waitForActivation() {
		return
	}

	controlQueue := s.controlQueue
	outboundQueue := s.outboundQueue

	for controlQueue != nil || outboundQueue != nil {
		var (
			msg outboundWrite
			ok  bool
		)

		select {
		case msg, ok = <-controlQueue:
			if !ok {
				controlQueue = nil
				continue
			}
		default:
			select {
			case msg, ok = <-controlQueue:
				if !ok {
					controlQueue = nil
					continue
				}
			case msg, ok = <-outboundQueue:
				if !ok {
					outboundQueue = nil
					continue
				}
			}
		}

		err := wire.SendProto(s.conn, msg.envelope)
		if err != nil {
			err = eris.Wrap(err, "send session envelope")
		}
		if msg.result != nil {
			select {
			case msg.result <- err:
			default:
			}
		}
		if err != nil {
			s.shutdown(err)
			return
		}
	}
}

func (s *Session) routeEnvelope(frame *sessionpb.Envelope) error {
	switch kind := frame.GetKind().(type) {
	case *sessionpb.Envelope_ChannelOpen:
		return s.enqueueDispatch(dispatchChannelOpen{message: kind.ChannelOpen})
	case *sessionpb.Envelope_ChannelOpenResult:
		return s.handleChannelOpenResult(kind.ChannelOpenResult)
	case *sessionpb.Envelope_ChannelData:
		return s.handleChannelData(kind.ChannelData)
	case *sessionpb.Envelope_ChannelWindowAdjust:
		return s.handleChannelWindowAdjust(kind.ChannelWindowAdjust)
	case *sessionpb.Envelope_ChannelEof:
		return s.enqueueChannelEvent(kind.ChannelEof.GetRecipientChannelId(), channelEvent{kind: channelEventEOF})
	case *sessionpb.Envelope_ChannelClose:
		return s.enqueueChannelEvent(kind.ChannelClose.GetRecipientChannelId(), channelEvent{kind: channelEventClose})
	case *sessionpb.Envelope_ChannelRequest:
		return s.enqueueChannelEvent(kind.ChannelRequest.GetRecipientChannelId(), channelEvent{
			kind:    channelEventRequest,
			request: kind.ChannelRequest,
		})
	case *sessionpb.Envelope_ChannelResult:
		return s.handleChannelResult(kind.ChannelResult)
	case *sessionpb.Envelope_GlobalRequest:
		return s.enqueueDispatch(dispatchGlobalRequest{message: kind.GlobalRequest})
	case *sessionpb.Envelope_GlobalResult:
		return s.handleGlobalResult(kind.GlobalResult)
	case *sessionpb.Envelope_Disconnect:
		return s.handleDisconnect(kind.Disconnect)
	default:
		return s.protocolErrorf("unsupported session frame %T", frame.GetKind())
	}
}

func (s *Session) handleChannelOpen(msg *sessionpb.ChannelOpen) error {
	if msg == nil {
		return s.protocolErrorf("received nil channel open")
	}

	s.mu.Lock()
	if _, exists := s.peerChannelIDs[msg.GetSenderChannelId()]; exists {
		s.mu.Unlock()
		return s.protocolErrorf("received duplicate peer channel id %d", msg.GetSenderChannelId())
	}
	s.mu.Unlock()

	localID := s.reserveLocalChannelID()
	ch := newIncomingChannel(s, localID, msg.GetSenderChannelId(), msg.GetChannelType(), msg.GetInitialWindow(), msg.GetMaxPacketSize(), nil)

	decision := s.handler.OnChannelOpen(s.Context(), ch, ChannelOpenRequest{
		Type:          msg.GetChannelType(),
		Payload:       cloneBytes(msg.GetPayload()),
		InitialWindow: msg.GetInitialWindow(),
		MaxPacketSize: msg.GetMaxPacketSize(),
	})
	if !decision.OK {
		ch.shutdown(errChannelClosed)
		return s.sendEnvelope(s.Context(), &sessionpb.Envelope{
			Kind: &sessionpb.Envelope_ChannelOpenResult{
				ChannelOpenResult: &sessionpb.ChannelOpenResult{
					RecipientChannelId: msg.GetSenderChannelId(),
					Result: &sessionpb.ChannelOpenResult_Reject{
						Reject: &sessionpb.ChannelOpenReject{
							Code:    normalizeRejectCode(decision.Code, "channel-open-rejected"),
							Message: normalizeRejectMessage(decision.Message, "channel open rejected"),
							Payload: cloneBytes(decision.Payload),
						},
					},
				},
			},
		})
	}

	ch.handler = normalizeChannelHandler(decision.Handler)

	s.mu.Lock()
	s.channels[localID] = ch
	s.peerChannelIDs[msg.GetSenderChannelId()] = localID
	s.mu.Unlock()

	s.startChannelWorker(ch)

	return s.sendEnvelope(s.Context(), &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelOpenResult{
			ChannelOpenResult: &sessionpb.ChannelOpenResult{
				RecipientChannelId: msg.GetSenderChannelId(),
				Result: &sessionpb.ChannelOpenResult_Success{
					Success: &sessionpb.ChannelOpenAccept{
						SenderChannelId: localID,
						InitialWindow:   s.config.InitialWindow,
						MaxPacketSize:   s.config.MaxPacketSize,
						Payload:         cloneBytes(decision.Payload),
					},
				},
			},
		},
	})
}

func (s *Session) handleChannelOpenResult(msg *sessionpb.ChannelOpenResult) error {
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel open result for unknown channel %d", msg.GetRecipientChannelId())
	}

	var openWait chan error
	var autoClose bool
	var openErr error

	ch.mu.Lock()
	if ch.openConfirmed || ch.openWait == nil {
		ch.mu.Unlock()
		return s.protocolErrorf("received duplicate channel open result for channel %d", msg.GetRecipientChannelId())
	}
	openWait = ch.openWait
	ch.openWait = nil

	switch result := msg.GetResult().(type) {
	case *sessionpb.ChannelOpenResult_Success:
		s.mu.Lock()
		if _, exists := s.peerChannelIDs[result.Success.GetSenderChannelId()]; exists {
			s.mu.Unlock()
			ch.mu.Unlock()
			return s.protocolErrorf("received duplicate peer channel id %d", result.Success.GetSenderChannelId())
		}
		s.peerChannelIDs[result.Success.GetSenderChannelId()] = ch.id
		s.mu.Unlock()

		ch.openConfirmed = true
		ch.peerID = result.Success.GetSenderChannelId()
		ch.localWindow = s.config.InitialWindow
		ch.remoteWindow = result.Success.GetInitialWindow()
		ch.maxLocalPacket = s.config.MaxPacketSize
		ch.maxRemotePacket = result.Success.GetMaxPacketSize()
		ch.signalLocked()
		autoClose = ch.openCanceled
	case *sessionpb.ChannelOpenResult_Reject:
		openErr = eris.Errorf("channel open rejected: %s", result.Reject.GetMessage())
		ch.signalLocked()
		ch.cancel(openErr)
	default:
		ch.mu.Unlock()
		return s.protocolErrorf("received invalid channel open result for channel %d", msg.GetRecipientChannelId())
	}
	ch.mu.Unlock()

	if openErr != nil {
		s.removeChannel(ch.id)
		ch.shutdown(openErr)
		select {
		case openWait <- openErr:
		default:
		}
		return nil
	}

	select {
	case openWait <- nil:
	default:
	}

	if autoClose {
		return ch.Close()
	}
	return nil
}

func (s *Session) handleChannelData(msg *sessionpb.ChannelData) error {
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel data for unknown channel %d", msg.GetRecipientChannelId())
	}

	frame := cloneBytes(msg.GetData())
	size := uint32(len(frame))

	ch.mu.Lock()
	defer ch.mu.Unlock()

	if !ch.openConfirmed {
		return s.protocolErrorf("received channel data before channel %d was opened", ch.id)
	}
	if ch.closeSent || ch.closeReceived {
		return s.protocolErrorf("received channel data after channel %d was closed", ch.id)
	}
	if size > ch.maxLocalPacket {
		return s.protocolErrorf("peer exceeded channel %d max packet size: %d > %d", ch.id, size, ch.maxLocalPacket)
	}
	if size > ch.localWindow {
		return s.protocolErrorf("peer exceeded channel %d window: %d > %d", ch.id, size, ch.localWindow)
	}

	ch.localWindow -= size
	ch.frames = append(ch.frames, frame)
	ch.signalLocked()
	return nil
}

func (s *Session) handleChannelWindowAdjust(msg *sessionpb.ChannelWindowAdjust) error {
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel window adjust for unknown channel %d", msg.GetRecipientChannelId())
	}

	ch.mu.Lock()
	defer ch.mu.Unlock()

	if !ch.openConfirmed {
		return s.protocolErrorf("received channel window adjust before channel %d was opened", ch.id)
	}
	if math.MaxUint32-ch.remoteWindow < msg.GetBytesToAdd() {
		return s.protocolErrorf("channel %d remote window overflow", ch.id)
	}

	ch.remoteWindow += msg.GetBytesToAdd()
	ch.signalLocked()
	return nil
}

func (s *Session) handleChannelResult(msg *sessionpb.ChannelResult) error {
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel result for unknown channel %d", msg.GetRecipientChannelId())
	}

	ch.mu.Lock()
	waitCh, ok := ch.pendingRequests[msg.GetRequestId()]
	if !ok {
		ch.mu.Unlock()
		return s.protocolErrorf("received channel result for unknown request %d on channel %d", msg.GetRequestId(), ch.id)
	}
	delete(ch.pendingRequests, msg.GetRequestId())
	ch.mu.Unlock()

	switch result := msg.GetResult().(type) {
	case *sessionpb.ChannelResult_Success:
		select {
		case waitCh <- channelWaitResult{
			response: &ChannelResponse{
				OK:      true,
				Payload: cloneBytes(result.Success.GetPayload()),
			},
		}:
		default:
		}
		return nil
	case *sessionpb.ChannelResult_Reject:
		select {
		case waitCh <- channelWaitResult{
			response: &ChannelResponse{
				OK:      false,
				Payload: cloneBytes(result.Reject.GetPayload()),
				Code:    result.Reject.GetCode(),
				Message: result.Reject.GetMessage(),
			},
		}:
		default:
		}
		return nil
	default:
		return s.protocolErrorf("received invalid channel result for request %d on channel %d", msg.GetRequestId(), ch.id)
	}
}

func (s *Session) handleGlobalRequest(msg *sessionpb.GlobalRequest) error {
	response := s.handler.OnGlobalRequest(s.Context(), GlobalRequest{
		Type:      msg.GetRequestType(),
		WantReply: msg.GetWantReply(),
		Payload:   cloneBytes(msg.GetPayload()),
	})
	if !msg.GetWantReply() {
		return nil
	}

	result := &sessionpb.GlobalResult{RequestId: msg.GetRequestId()}
	if response.OK {
		result.Result = &sessionpb.GlobalResult_Success{
			Success: &sessionpb.OperationSuccess{Payload: cloneBytes(response.Payload)},
		}
	} else {
		result.Result = &sessionpb.GlobalResult_Reject{
			Reject: &sessionpb.OperationReject{
				Code:    normalizeRejectCode(response.Code, "global-request-rejected"),
				Message: normalizeRejectMessage(response.Message, "global request rejected"),
				Payload: cloneBytes(response.Payload),
			},
		}
	}

	return s.sendEnvelope(s.Context(), &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_GlobalResult{GlobalResult: result},
	})
}

func (s *Session) handleGlobalResult(msg *sessionpb.GlobalResult) error {
	s.mu.Lock()
	waitCh, ok := s.pendingGlobal[msg.GetRequestId()]
	if ok {
		delete(s.pendingGlobal, msg.GetRequestId())
	}
	s.mu.Unlock()

	if !ok {
		return s.protocolErrorf("received global result for unknown request %d", msg.GetRequestId())
	}

	switch result := msg.GetResult().(type) {
	case *sessionpb.GlobalResult_Success:
		select {
		case waitCh <- globalWaitResult{
			response: &GlobalResponse{
				OK:      true,
				Payload: cloneBytes(result.Success.GetPayload()),
			},
		}:
		default:
		}
		return nil
	case *sessionpb.GlobalResult_Reject:
		select {
		case waitCh <- globalWaitResult{
			response: &GlobalResponse{
				OK:      false,
				Payload: cloneBytes(result.Reject.GetPayload()),
				Code:    result.Reject.GetCode(),
				Message: result.Reject.GetMessage(),
			},
		}:
		default:
		}
		return nil
	default:
		return s.protocolErrorf("received invalid global result for request %d", msg.GetRequestId())
	}
}

func (s *Session) handleDisconnect(msg *sessionpb.Disconnect) error {
	if msg == nil {
		return eris.New("remote disconnected")
	}
	if code := msg.GetCode(); code != "" {
		return eris.Errorf("remote disconnect (%s): %s", code, msg.GetMessage())
	}
	return eris.Errorf("remote disconnect: %s", msg.GetMessage())
}

func (s *Session) sendEnvelope(ctx context.Context, frame *sessionpb.Envelope) error {
	ctx = normalizeContext(ctx)
	if frame == nil {
		return eris.New("session envelope is required")
	}
	if err := s.ensureActive(); err != nil {
		return err
	}

	result := make(chan error, 1)
	if err := s.enqueueWrite(outboundWrite{
		envelope: frame,
		result:   result,
	}, false); err != nil {
		return err
	}

	select {
	case err := <-result:
		if err != nil {
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.Context().Done():
		return s.closeCause()
	}
}

func (s *Session) enqueueWrite(msg outboundWrite, control bool) error {
	if msg.envelope == nil {
		return eris.New("session envelope is required")
	}

	s.queueMu.Lock()
	defer s.queueMu.Unlock()

	if s.queuesClosed {
		return s.closeCause()
	}

	queue := s.outboundQueue
	if control {
		queue = s.controlQueue
	}

	select {
	case queue <- msg:
		return nil
	default:
	}

	err := eris.New("session outbound queue exhausted")
	go s.shutdown(err)
	return err
}

func (s *Session) enqueueDispatch(task dispatchTask) error {
	select {
	case s.dispatchQueue <- task:
		return nil
	default:
		return s.queueExhausted("connection dispatch queue exhausted")
	}
}

func (s *Session) enqueueChannelEvent(localID uint64, event channelEvent) error {
	ch := s.lookupChannel(localID)
	if ch == nil {
		return s.protocolErrorf("received channel frame for unknown channel %d", localID)
	}
	return ch.enqueueEvent(event)
}

func (s *Session) queueExhausted(message string) error {
	err := eris.New(message)
	go s.shutdown(err)
	return err
}

func (s *Session) ensureActive() error {
	if s == nil {
		return eris.New("session is required")
	}

	select {
	case <-s.activated:
	default:
		return errSessionNotActive
	}

	select {
	case <-s.Context().Done():
		return s.closeCause()
	default:
		return nil
	}
}

func (s *Session) waitForActivation() bool {
	select {
	case <-s.activated:
		return true
	case <-s.Context().Done():
		return false
	}
}

func (s *Session) startChannelWorker(ch *Channel) {
	s.wg.Add(1)
	go ch.loop()
}

func (s *Session) reserveLocalChannelID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	localID := s.nextLocalChannelID
	s.nextLocalChannelID++
	return localID
}

func (s *Session) lookupChannel(id uint64) *Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.channels[id]
}

func (s *Session) removeChannel(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeChannelLocked(id)
}

func (s *Session) removeChannelLocked(id uint64) {
	ch, ok := s.channels[id]
	if !ok {
		return
	}
	delete(s.channels, id)
	if ch.openConfirmed {
		delete(s.peerChannelIDs, ch.peerID)
	}
}

func (s *Session) protocolErrorf(format string, args ...any) error {
	return &protocolError{message: fmt.Sprintf(format, args...)}
}

func (s *Session) closeCause() error {
	if s == nil {
		return context.Canceled
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeErr != nil {
		return s.closeErr
	}
	if cause := context.Cause(s.Context()); cause != nil {
		return cause
	}
	return context.Canceled
}

func (s *Session) shutdown(err error) {
	s.shutdownOnce.Do(func() {
		waitErr := err
		closeErr := err
		if waitErr == nil {
			closeErr = errSessionClosed
		}
		if closeErr == nil {
			closeErr = context.Canceled
		}

		s.mu.Lock()
		s.waitErr = waitErr
		s.closeErr = closeErr
		s.closing = true

		channels := make([]*Channel, 0, len(s.channels))
		for _, ch := range s.channels {
			channels = append(channels, ch)
		}

		pendingGlobal := make([]chan globalWaitResult, 0, len(s.pendingGlobal))
		for _, waitCh := range s.pendingGlobal {
			pendingGlobal = append(pendingGlobal, waitCh)
		}
		s.pendingGlobal = make(map[uint64]chan globalWaitResult)
		s.channels = make(map[uint64]*Channel)
		s.peerChannelIDs = make(map[uint64]uint64)
		s.mu.Unlock()

		if protocolErr, ok := err.(*protocolError); ok {
			_ = s.enqueueWrite(outboundWrite{
				envelope: &sessionpb.Envelope{
					Kind: &sessionpb.Envelope_Disconnect{
						Disconnect: &sessionpb.Disconnect{
							Code:    "protocol-error",
							Message: protocolErr.message,
						},
					},
				},
			}, true)
		}

		s.cancel(closeErr)

		for _, ch := range channels {
			ch.shutdown(closeErr)
		}
		for _, waitCh := range pendingGlobal {
			select {
			case waitCh <- globalWaitResult{err: closeErr}:
			default:
			}
		}

		s.queueMu.Lock()
		if !s.queuesClosed {
			close(s.controlQueue)
			close(s.outboundQueue)
			s.queuesClosed = true
		}
		s.queueMu.Unlock()

		go s.finalize(err)
	})
}

func (s *Session) finalize(cause error) {
	if _, ok := cause.(*protocolError); ok {
		timer := time.NewTimer(s.config.DisconnectTimeout)
		select {
		case <-s.writerDone:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}

	s.closeUnderlyingConn()
	s.wg.Wait()
	close(s.done)
}

func (s *Session) closeUnderlyingConn() {
	s.closeConn.Do(func() {
		if s.conn == nil {
			return
		}
		if err := s.conn.Close(); err != nil {
			s.logger.Debug("session close cleanup failed", "err", err)
		}
	})
}

func cloneBytes(data []byte) []byte {
	return append([]byte(nil), data...)
}

func normalizeRejectCode(code string, fallback string) string {
	if code == "" {
		return fallback
	}
	return code
}

func normalizeRejectMessage(message string, fallback string) string {
	if message == "" {
		return fallback
	}
	return message
}

func (task dispatchChannelOpen) dispatch(s *Session) error {
	return s.handleChannelOpen(task.message)
}

func (task dispatchGlobalRequest) dispatch(s *Session) error {
	return s.handleGlobalRequest(task.message)
}
