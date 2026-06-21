package session

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/rotisserie/eris"
	"google.golang.org/protobuf/proto"
)

type Prepared struct {
	config  Config
	handler Handler
}

type globalWaitResult struct {
	response *GlobalResponse
	err      error
}

const (
	writeQueued uint32 = iota
	writeStarted
	writeCanceled
	writeDone
)

type outboundWrite struct {
	envelope *sessionpb.Envelope
	result   chan error
	after    func(error)
	size     uint64
	state    atomic.Uint32
}

type dispatchTask interface {
	dispatch(*Session) error
	size() uint64
}

type dispatchChannelOpen struct {
	message *sessionpb.ChannelOpen
}

func (d dispatchChannelOpen) size() uint64 {
	return uint64(proto.Size(d.message))
}

type dispatchGlobalRequest struct {
	message *sessionpb.GlobalRequest
}

func (d dispatchGlobalRequest) size() uint64 {
	return uint64(proto.Size(d.message))
}

type protocolError struct {
	message string
}

func (e *protocolError) Error() string {
	return e.message
}

type channelSlot uint8

const (
	channelSlotNone channelSlot = iota
	channelSlotPending
	channelSlotActive
)

type Session struct {
	conn   wire.FramedConn
	logger *slog.Logger
	config Config

	ctx    context.Context
	cancel context.CancelCauseFunc

	mu                     sync.Mutex
	nextLocalChannelID     uint64
	channels               map[uint64]*Channel
	peerChannelIDs         map[uint64]uint64
	activeChannels         uint32
	pendingOpens           uint32
	nextGlobalRequestID    uint64
	pendingGlobal          map[uint64]chan globalWaitResult
	incomingGlobalRequests map[uint64]struct{}
	pendingChannelRequests uint32
	waitErr                error
	closeErr               error
	closing                bool

	budgetMu      sync.Mutex
	queuedFrames  uint32
	queuedBytes   uint64
	queueMu       sync.Mutex
	queuesClosed  bool
	dispatchQueue chan dispatchTask
	controlQueue  chan *outboundWrite
	outboundQueue chan *outboundWrite

	activated  chan struct{}
	done       chan struct{}
	writerDone chan struct{}

	wg           sync.WaitGroup
	activateOnce sync.Once
	shutdownOnce sync.Once
	closeConn    sync.Once
	stopParent   func() bool
	handler      Handler
}

func Prepare(cfg Config, handler Handler) (*Prepared, error) {
	if err := cfg.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate session mux config")
	}

	return &Prepared{
		config:  cfg.withDefaults(),
		handler: normalizeHandler(handler),
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
	if err := context.Cause(parent); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancelCause(parent)
	queueCapacity := int(p.config.Limits.MaxQueuedFramesTotal)
	s := &Session{
		conn:                   conn,
		logger:                 slog.Default().With("component", "session"),
		config:                 p.config,
		ctx:                    ctx,
		cancel:                 cancel,
		channels:               make(map[uint64]*Channel),
		peerChannelIDs:         make(map[uint64]uint64),
		pendingGlobal:          make(map[uint64]chan globalWaitResult),
		incomingGlobalRequests: make(map[uint64]struct{}),
		dispatchQueue:          make(chan dispatchTask, queueCapacity),
		controlQueue:           make(chan *outboundWrite, queueCapacity),
		outboundQueue:          make(chan *outboundWrite, queueCapacity),
		activated:              make(chan struct{}),
		done:                   make(chan struct{}),
		writerDone:             make(chan struct{}),
		handler:                p.handler,
	}
	s.stopParent = context.AfterFunc(parent, func() {
		s.shutdown(context.Cause(parent))
	})

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
	if err := s.validateTypeAndPayload(typ, payload); err != nil {
		return nil, err
	}
	if err := s.ensureActive(); err != nil {
		return nil, err
	}

	localID, err := s.reserveLocalChannelID()
	if err != nil {
		return nil, err
	}
	ch := newPendingChannel(s, localID, typ, handler)
	if err := s.addPendingChannel(ch, nil); err != nil {
		return nil, err
	}
	waitCh := ch.openWait

	err = s.sendEnvelope(ctx, &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelOpen{
			ChannelOpen: &sessionpb.ChannelOpen{
				ChannelType:     typ,
				SenderChannelId: localID,
				InitialWindow:   s.config.InitialWindow,
				MaxPacketSize:   s.config.MaxPacketSize,
				Payload:         cloneBytes(payload),
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
		s.abandonOpen(ch, ctx.Err())
		return nil, ctx.Err()
	case <-s.Context().Done():
		s.abandonOpen(ch, s.closeCause())
		return nil, s.closeCause()
	}
}

func (s *Session) SendGlobalRequest(ctx context.Context, typ string, payload []byte, wantReply bool) (*GlobalResponse, error) {
	ctx = normalizeContext(ctx)
	if err := s.validateTypeAndPayload(typ, payload); err != nil {
		return nil, err
	}
	if err := s.ensureActive(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.nextGlobalRequestID == math.MaxUint64 {
		s.mu.Unlock()
		return nil, eris.New("global request id space exhausted")
	}
	requestID := s.nextGlobalRequestID
	s.nextGlobalRequestID++

	var waitCh chan globalWaitResult
	if wantReply {
		if uint32(len(s.pendingGlobal)) >= s.config.Limits.MaxPendingGlobalRequests {
			s.mu.Unlock()
			return nil, eris.New("pending global request limit reached")
		}
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
				Payload:     cloneBytes(payload),
			},
		},
	})
	if err != nil {
		if wantReply {
			s.removeGlobalWaiter(requestID, waitCh)
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
		s.removeGlobalWaiter(requestID, waitCh)
		return nil, ctx.Err()
	case <-s.Context().Done():
		s.removeGlobalWaiter(requestID, waitCh)
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
		case task, ok := <-s.dispatchQueue:
			if !ok {
				return
			}
			s.releaseQueueBudget(1, task.size())
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
			msg *outboundWrite
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

		s.releaseQueueBudget(1, msg.size)
		if !msg.state.CompareAndSwap(writeQueued, writeStarted) {
			if msg.after != nil {
				msg.after(context.Canceled)
			}
			if msg.result != nil {
				select {
				case msg.result <- context.Canceled:
				default:
				}
			}
			continue
		}

		err := wire.SendProto(s.conn, msg.envelope)
		if err != nil {
			err = eris.Wrap(err, "send session envelope")
		}
		if msg.after != nil {
			msg.after(err)
		}
		msg.state.Store(writeDone)
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
		return s.enqueueIncomingOpen(kind.ChannelOpen)
	case *sessionpb.Envelope_ChannelOpenResult:
		return s.handleChannelOpenResult(kind.ChannelOpenResult)
	case *sessionpb.Envelope_ChannelData:
		return s.handleChannelData(kind.ChannelData)
	case *sessionpb.Envelope_ChannelWindowAdjust:
		return s.handleChannelWindowAdjust(kind.ChannelWindowAdjust)
	case *sessionpb.Envelope_ChannelEof:
		return s.enqueueChannelEOF(kind.ChannelEof.GetRecipientChannelId())
	case *sessionpb.Envelope_ChannelClose:
		return s.enqueueChannelClose(kind.ChannelClose.GetRecipientChannelId())
	case *sessionpb.Envelope_ChannelRequest:
		return s.enqueueChannelRequest(kind.ChannelRequest)
	case *sessionpb.Envelope_ChannelResult:
		return s.handleChannelResult(kind.ChannelResult)
	case *sessionpb.Envelope_GlobalRequest:
		return s.enqueueGlobalRequest(kind.GlobalRequest)
	case *sessionpb.Envelope_GlobalResult:
		return s.handleGlobalResult(kind.GlobalResult)
	case *sessionpb.Envelope_Disconnect:
		return s.handleDisconnect(kind.Disconnect)
	default:
		return s.protocolErrorf("unsupported session frame %T", frame.GetKind())
	}
}

func (s *Session) enqueueIncomingOpen(msg *sessionpb.ChannelOpen) error {
	if msg == nil {
		return s.protocolErrorf("received nil channel open")
	}
	if err := s.validateTypeAndPayload(msg.GetChannelType(), msg.GetPayload()); err != nil {
		return s.protocolErrorf("invalid channel open: %v", err)
	}
	localID, err := s.reserveLocalChannelID()
	if err != nil {
		return err
	}
	ch := newIncomingChannel(s, localID, msg.GetSenderChannelId(), msg.GetChannelType(), msg.GetInitialWindow(), msg.GetMaxPacketSize(), nil)
	if err := s.addPendingChannel(ch, &msg.SenderChannelId); err != nil {
		if eris.Is(err, errResourceLimit) {
			return s.sendChannelOpenRejectAsync(msg.GetSenderChannelId(), "resource-limit", "channel limit reached")
		}
		return err
	}

	task := dispatchChannelOpen{message: msg}
	if err := s.enqueueDispatch(task); err != nil {
		s.removeChannel(localID)
		ch.shutdown(err)
		if eris.Is(err, errResourceLimit) {
			return s.sendChannelOpenRejectAsync(msg.GetSenderChannelId(), "resource-limit", "channel queue limit reached")
		}
		return err
	}
	return nil
}

func (s *Session) handleChannelOpen(msg *sessionpb.ChannelOpen) error {
	ch := s.lookupChannelByPeer(msg.GetSenderChannelId())
	if ch == nil {
		return s.protocolErrorf("pending channel %d disappeared during admission", msg.GetSenderChannelId())
	}

	decision := s.handler.OnChannelOpen(s.Context(), ChannelOpenRequest{
		Type:          msg.GetChannelType(),
		Payload:       cloneBytes(msg.GetPayload()),
		InitialWindow: msg.GetInitialWindow(),
		MaxPacketSize: msg.GetMaxPacketSize(),
	})
	if err := s.validateDecision(decision); err != nil {
		s.removeChannel(ch.id)
		ch.shutdown(err)
		return err
	}
	if !decision.OK {
		s.removeChannel(ch.id)
		ch.shutdown(errChannelClosed)
		return s.sendChannelOpenReject(
			msg.GetSenderChannelId(),
			normalizeRejectCode(decision.Code, "channel-open-rejected"),
			normalizeRejectMessage(decision.Message, "channel open rejected"),
			decision.Payload,
		)
	}

	ch.mu.Lock()
	ch.handler = normalizeChannelHandler(decision.Handler)
	if ch.state != channelOpening {
		ch.mu.Unlock()
		return s.protocolErrorf("channel %d changed state during admission", ch.id)
	}
	ch.state = channelOpen
	ch.signalLocked()
	ch.mu.Unlock()
	if err := s.activateChannel(ch); err != nil {
		return err
	}

	err := s.sendEnvelopeAfter(s.Context(), &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelOpenResult{
			ChannelOpenResult: &sessionpb.ChannelOpenResult{
				RecipientChannelId: msg.GetSenderChannelId(),
				Result: &sessionpb.ChannelOpenResult_Success{
					Success: &sessionpb.ChannelOpenAccept{
						SenderChannelId: ch.id,
						InitialWindow:   s.config.InitialWindow,
						MaxPacketSize:   s.config.MaxPacketSize,
						Payload:         cloneBytes(decision.Payload),
					},
				},
			},
		},
	}, func(sendErr error) {
		if sendErr != nil {
			return
		}
		s.startChannelWorker(ch)
	})
	if err != nil {
		s.removeChannel(ch.id)
		ch.shutdown(err)
	}
	return err
}

func (s *Session) handleChannelOpenResult(msg *sessionpb.ChannelOpenResult) error {
	if msg == nil {
		return s.protocolErrorf("received nil channel open result")
	}
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel open result for unknown channel %d", msg.GetRecipientChannelId())
	}

	ch.mu.Lock()
	if ch.state != channelOpening || ch.openWait == nil {
		ch.mu.Unlock()
		return s.protocolErrorf("received duplicate channel open result for channel %d", msg.GetRecipientChannelId())
	}
	openWait := ch.openWait
	ch.openWait = nil

	switch result := msg.GetResult().(type) {
	case *sessionpb.ChannelOpenResult_Success:
		if uint32(len(result.Success.GetPayload())) > s.config.Limits.MaxControlPayload {
			ch.mu.Unlock()
			return s.protocolErrorf("channel open result payload exceeds configured limit")
		}
		if err := s.reservePeerChannelID(result.Success.GetSenderChannelId(), ch.id); err != nil {
			ch.mu.Unlock()
			return err
		}
		ch.peerID = result.Success.GetSenderChannelId()
		ch.localWindow = s.config.InitialWindow
		ch.remoteWindow = result.Success.GetInitialWindow()
		ch.maxLocalPacket = s.config.MaxPacketSize
		ch.maxRemotePacket = result.Success.GetMaxPacketSize()
		ch.state = channelOpen
		ch.signalLocked()
		ch.mu.Unlock()

		if err := s.activateChannel(ch); err != nil {
			return err
		}
		s.startChannelWorker(ch)
		select {
		case openWait <- nil:
		default:
		}
		return nil
	case *sessionpb.ChannelOpenResult_Reject:
		if err := s.validateResponse(result.Reject.GetCode(), result.Reject.GetMessage(), result.Reject.GetPayload()); err != nil {
			ch.mu.Unlock()
			return s.protocolErrorf("invalid channel open rejection: %v", err)
		}
		openErr := eris.Errorf("channel open rejected: %s", result.Reject.GetMessage())
		ch.state = channelFailed
		ch.signalLocked()
		ch.mu.Unlock()
		s.removeChannel(ch.id)
		ch.shutdown(openErr)
		select {
		case openWait <- openErr:
		default:
		}
		return nil
	default:
		ch.mu.Unlock()
		return s.protocolErrorf("received invalid channel open result for channel %d", msg.GetRecipientChannelId())
	}
}

func (s *Session) handleChannelData(msg *sessionpb.ChannelData) error {
	if msg == nil {
		return s.protocolErrorf("received nil channel data")
	}
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel data for unknown channel %d", msg.GetRecipientChannelId())
	}

	frame := cloneBytes(msg.GetData())
	if len(frame) == 0 {
		return s.protocolErrorf("received empty channel data for channel %d", ch.id)
	}
	size := uint32(len(frame))

	ch.mu.Lock()
	defer ch.mu.Unlock()
	if !ch.state.canReceiveData() {
		return s.protocolErrorf("received channel data while channel %d is %s", ch.id, ch.state)
	}
	if size > ch.maxLocalPacket {
		return s.protocolErrorf("peer exceeded channel %d max packet size: %d > %d", ch.id, size, ch.maxLocalPacket)
	}
	if size > ch.localWindow {
		return s.protocolErrorf("peer exceeded channel %d window: %d > %d", ch.id, size, ch.localWindow)
	}
	if err := ch.reserveQueuedLocked(1, uint64(size)); err != nil {
		return err
	}

	ch.localWindow -= size
	ch.frames = append(ch.frames, frame)
	ch.signalLocked()
	return nil
}

func (s *Session) handleChannelWindowAdjust(msg *sessionpb.ChannelWindowAdjust) error {
	if msg == nil {
		return s.protocolErrorf("received nil channel window adjustment")
	}
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel window adjust for unknown channel %d", msg.GetRecipientChannelId())
	}

	ch.mu.Lock()
	defer ch.mu.Unlock()
	if !ch.state.allowsRequests() {
		return s.protocolErrorf("received channel window adjust while channel %d is %s", ch.id, ch.state)
	}
	if math.MaxUint32-ch.remoteWindow < msg.GetBytesToAdd() {
		return s.protocolErrorf("channel %d remote window overflow", ch.id)
	}

	ch.remoteWindow += msg.GetBytesToAdd()
	ch.signalLocked()
	return nil
}

func (s *Session) handleChannelResult(msg *sessionpb.ChannelResult) error {
	if msg == nil {
		return s.protocolErrorf("received nil channel result")
	}
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel result for unknown channel %d", msg.GetRecipientChannelId())
	}

	ch.mu.Lock()
	waitCh, ok := ch.pendingRequests[msg.GetRequestId()]
	if ok {
		delete(ch.pendingRequests, msg.GetRequestId())
	}
	ch.mu.Unlock()
	if !ok {
		return s.protocolErrorf("received channel result for unknown request %d on channel %d", msg.GetRequestId(), ch.id)
	}
	s.releasePendingChannelRequest()

	switch result := msg.GetResult().(type) {
	case *sessionpb.ChannelResult_Success:
		if uint32(len(result.Success.GetPayload())) > s.config.Limits.MaxControlPayload {
			return s.protocolErrorf("channel result payload exceeds configured limit")
		}
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
		if err := s.validateResponse(result.Reject.GetCode(), result.Reject.GetMessage(), result.Reject.GetPayload()); err != nil {
			return s.protocolErrorf("invalid channel rejection: %v", err)
		}
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

func (s *Session) enqueueGlobalRequest(msg *sessionpb.GlobalRequest) error {
	if msg == nil {
		return s.protocolErrorf("received nil global request")
	}
	if err := s.validateTypeAndPayload(msg.GetRequestType(), msg.GetPayload()); err != nil {
		return s.protocolErrorf("invalid global request: %v", err)
	}

	if msg.GetWantReply() {
		s.mu.Lock()
		if _, exists := s.incomingGlobalRequests[msg.GetRequestId()]; exists {
			s.mu.Unlock()
			return s.protocolErrorf("received duplicate global request id %d", msg.GetRequestId())
		}
		s.incomingGlobalRequests[msg.GetRequestId()] = struct{}{}
		s.mu.Unlock()
	}

	task := dispatchGlobalRequest{message: msg}
	if err := s.enqueueDispatch(task); err != nil {
		if eris.Is(err, errResourceLimit) && msg.GetWantReply() {
			sendErr := s.sendGlobalRejectAsync(
				msg.GetRequestId(),
				"resource-limit",
				"global request queue limit reached",
				func(error) {
					s.finishIncomingGlobal(msg.GetRequestId(), true)
				},
			)
			if sendErr != nil {
				s.finishIncomingGlobal(msg.GetRequestId(), true)
			}
			return sendErr
		}
		s.finishIncomingGlobal(msg.GetRequestId(), msg.GetWantReply())
		return err
	}
	return nil
}

func (s *Session) handleGlobalRequest(msg *sessionpb.GlobalRequest) error {
	defer s.finishIncomingGlobal(msg.GetRequestId(), msg.GetWantReply())

	response := s.handler.OnGlobalRequest(s.Context(), GlobalRequest{
		Type:      msg.GetRequestType(),
		WantReply: msg.GetWantReply(),
		Payload:   cloneBytes(msg.GetPayload()),
	})
	if !msg.GetWantReply() {
		return nil
	}
	if err := s.validateResponse(response.Code, response.Message, response.Payload); err != nil {
		return err
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
	if msg == nil {
		return s.protocolErrorf("received nil global result")
	}
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
		if uint32(len(result.Success.GetPayload())) > s.config.Limits.MaxControlPayload {
			return s.protocolErrorf("global result payload exceeds configured limit")
		}
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
		if err := s.validateResponse(result.Reject.GetCode(), result.Reject.GetMessage(), result.Reject.GetPayload()); err != nil {
			return s.protocolErrorf("invalid global rejection: %v", err)
		}
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
	if err := s.validateResponse(msg.GetCode(), msg.GetMessage(), nil); err != nil {
		return s.protocolErrorf("invalid disconnect: %v", err)
	}
	if code := msg.GetCode(); code != "" {
		return eris.Errorf("remote disconnect (%s): %s", code, msg.GetMessage())
	}
	return eris.Errorf("remote disconnect: %s", msg.GetMessage())
}

func (s *Session) sendEnvelope(ctx context.Context, frame *sessionpb.Envelope) error {
	return s.sendEnvelopeAfter(ctx, frame, nil)
}

func (s *Session) sendEnvelopeAfter(ctx context.Context, frame *sessionpb.Envelope, after func(error)) error {
	ctx = normalizeContext(ctx)
	if frame == nil {
		return eris.New("session envelope is required")
	}
	if err := s.ensureActive(); err != nil {
		return err
	}

	result := make(chan error, 1)
	msg := &outboundWrite{
		envelope: frame,
		result:   result,
		after:    after,
		size:     uint64(proto.Size(frame)),
	}
	if err := s.enqueueWrite(msg, false); err != nil {
		return err
	}

	for {
		select {
		case err := <-result:
			return err
		case <-ctx.Done():
			if msg.state.CompareAndSwap(writeQueued, writeCanceled) {
				return ctx.Err()
			}
		case <-s.Context().Done():
			if msg.state.CompareAndSwap(writeQueued, writeCanceled) {
				return s.closeCause()
			}
		}
	}
}

func (s *Session) sendEnvelopeAsync(frame *sessionpb.Envelope, control bool) error {
	return s.sendEnvelopeAsyncAfter(frame, control, nil)
}

func (s *Session) sendEnvelopeAsyncAfter(frame *sessionpb.Envelope, control bool, after func(error)) error {
	if frame == nil {
		return eris.New("session envelope is required")
	}
	msg := &outboundWrite{
		envelope: frame,
		size:     uint64(proto.Size(frame)),
		after:    after,
	}
	return s.enqueueWrite(msg, control)
}

func (s *Session) enqueueWrite(msg *outboundWrite, control bool) error {
	if msg == nil || msg.envelope == nil {
		return eris.New("session envelope is required")
	}
	if err := s.reserveQueueBudget(1, msg.size); err != nil {
		return err
	}

	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	if s.queuesClosed {
		s.releaseQueueBudget(1, msg.size)
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
		s.releaseQueueBudget(1, msg.size)
	}

	err := eris.New("session outbound queue exhausted")
	go s.shutdown(err)
	return err
}

func (s *Session) enqueueDispatch(task dispatchTask) error {
	if err := s.reserveQueueBudget(1, task.size()); err != nil {
		return err
	}
	select {
	case s.dispatchQueue <- task:
		return nil
	default:
		s.releaseQueueBudget(1, task.size())
		return errResourceLimit
	}
}

func (s *Session) reserveQueueBudget(frames uint32, bytes uint64) error {
	s.budgetMu.Lock()
	defer s.budgetMu.Unlock()
	if frames > s.config.Limits.MaxQueuedFramesTotal-s.queuedFrames {
		return errResourceLimit
	}
	if bytes > s.config.Limits.MaxQueuedBytesTotal-s.queuedBytes {
		return errResourceLimit
	}
	s.queuedFrames += frames
	s.queuedBytes += bytes
	return nil
}

func (s *Session) releaseQueueBudget(frames uint32, bytes uint64) {
	s.budgetMu.Lock()
	defer s.budgetMu.Unlock()
	if frames > s.queuedFrames {
		s.queuedFrames = 0
	} else {
		s.queuedFrames -= frames
	}
	if bytes > s.queuedBytes {
		s.queuedBytes = 0
	} else {
		s.queuedBytes -= bytes
	}
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

func (s *Session) reserveLocalChannelID() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextLocalChannelID == math.MaxUint64 {
		return 0, eris.New("local channel id space exhausted")
	}
	localID := s.nextLocalChannelID
	s.nextLocalChannelID++
	return localID, nil
}

func (s *Session) addPendingChannel(ch *Channel, peerID *uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingOpens >= s.config.Limits.MaxPendingOpens ||
		s.activeChannels+s.pendingOpens >= s.config.Limits.MaxChannels {
		return errResourceLimit
	}
	if peerID != nil {
		if _, exists := s.peerChannelIDs[*peerID]; exists {
			return s.protocolErrorf("received duplicate peer channel id %d", *peerID)
		}
		s.peerChannelIDs[*peerID] = ch.id
	}
	ch.slot = channelSlotPending
	s.channels[ch.id] = ch
	s.pendingOpens++
	return nil
}

func (s *Session) reservePeerChannelID(peerID uint64, localID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.peerChannelIDs[peerID]; exists {
		return s.protocolErrorf("received duplicate peer channel id %d", peerID)
	}
	s.peerChannelIDs[peerID] = localID
	return nil
}

func (s *Session) activateChannel(ch *Channel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch.slot != channelSlotPending {
		return eris.Errorf("channel %d is not pending activation", ch.id)
	}
	if s.pendingOpens == 0 {
		return eris.New("pending channel accounting underflow")
	}
	s.pendingOpens--
	s.activeChannels++
	ch.slot = channelSlotActive
	return nil
}

func (s *Session) lookupChannel(id uint64) *Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.channels[id]
}

func (s *Session) lookupChannelByPeer(peerID uint64) *Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	localID, ok := s.peerChannelIDs[peerID]
	if !ok {
		return nil
	}
	return s.channels[localID]
}

func (s *Session) removeChannel(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.channels[id]
	if !ok {
		return
	}
	delete(s.channels, id)
	for peerID, localID := range s.peerChannelIDs {
		if localID == id {
			delete(s.peerChannelIDs, peerID)
		}
	}
	switch ch.slot {
	case channelSlotPending:
		if s.pendingOpens > 0 {
			s.pendingOpens--
		}
	case channelSlotActive:
		if s.activeChannels > 0 {
			s.activeChannels--
		}
	}
	ch.slot = channelSlotNone
}

func (s *Session) abandonOpen(ch *Channel, cause error) {
	ch.mu.Lock()
	if ch.state == channelOpening {
		ch.state = channelFailed
		ch.openWait = nil
		ch.signalLocked()
		ch.mu.Unlock()
		s.removeChannel(ch.id)
		ch.shutdown(cause)
		return
	}
	ch.mu.Unlock()
	_ = ch.Close()
}

func (s *Session) removeGlobalWaiter(requestID uint64, waitCh chan globalWaitResult) {
	s.mu.Lock()
	if current, ok := s.pendingGlobal[requestID]; ok && current == waitCh {
		delete(s.pendingGlobal, requestID)
	}
	s.mu.Unlock()
}

func (s *Session) reservePendingChannelRequest() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingChannelRequests >= s.config.Limits.MaxPendingChannelRequests {
		return eris.New("pending channel request limit reached")
	}
	s.pendingChannelRequests++
	return nil
}

func (s *Session) releasePendingChannelRequest() {
	s.mu.Lock()
	if s.pendingChannelRequests > 0 {
		s.pendingChannelRequests--
	}
	s.mu.Unlock()
}

func (s *Session) finishIncomingGlobal(requestID uint64, wantReply bool) {
	if !wantReply {
		return
	}
	s.mu.Lock()
	delete(s.incomingGlobalRequests, requestID)
	s.mu.Unlock()
}

func (s *Session) sendChannelOpenReject(peerID uint64, code string, message string, payload []byte) error {
	return s.sendEnvelope(s.Context(), &sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelOpenResult{
			ChannelOpenResult: &sessionpb.ChannelOpenResult{
				RecipientChannelId: peerID,
				Result: &sessionpb.ChannelOpenResult_Reject{
					Reject: &sessionpb.ChannelOpenReject{
						Code:    code,
						Message: message,
						Payload: cloneBytes(payload),
					},
				},
			},
		},
	})
}

func (s *Session) sendChannelOpenRejectAsync(peerID uint64, code string, message string) error {
	return s.sendEnvelopeAsync(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelOpenResult{
			ChannelOpenResult: &sessionpb.ChannelOpenResult{
				RecipientChannelId: peerID,
				Result: &sessionpb.ChannelOpenResult_Reject{
					Reject: &sessionpb.ChannelOpenReject{
						Code:    code,
						Message: message,
					},
				},
			},
		},
	}, true)
}

func (s *Session) sendGlobalRejectAsync(requestID uint64, code string, message string, after func(error)) error {
	return s.sendEnvelopeAsyncAfter(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_GlobalResult{
			GlobalResult: &sessionpb.GlobalResult{
				RequestId: requestID,
				Result: &sessionpb.GlobalResult_Reject{
					Reject: &sessionpb.OperationReject{Code: code, Message: message},
				},
			},
		},
	}, true, after)
}

func (s *Session) validateTypeAndPayload(typ string, payload []byte) error {
	if typ == "" {
		return eris.New("request type is required")
	}
	if uint32(len(typ)) > s.config.Limits.MaxTypeLength {
		return eris.Errorf("request type exceeds limit: %d > %d", len(typ), s.config.Limits.MaxTypeLength)
	}
	if uint32(len(payload)) > s.config.Limits.MaxControlPayload {
		return eris.Errorf("control payload exceeds limit: %d > %d", len(payload), s.config.Limits.MaxControlPayload)
	}
	return nil
}

func (s *Session) validateResponse(code string, message string, payload []byte) error {
	if uint32(len(code)) > s.config.Limits.MaxCodeLength {
		return eris.Errorf("response code exceeds limit: %d > %d", len(code), s.config.Limits.MaxCodeLength)
	}
	if uint32(len(message)) > s.config.Limits.MaxMessageLength {
		return eris.Errorf("response message exceeds limit: %d > %d", len(message), s.config.Limits.MaxMessageLength)
	}
	if uint32(len(payload)) > s.config.Limits.MaxControlPayload {
		return eris.Errorf("response payload exceeds limit: %d > %d", len(payload), s.config.Limits.MaxControlPayload)
	}
	return nil
}

func (s *Session) validateDecision(decision ChannelOpenDecision) error {
	return s.validateResponse(decision.Code, decision.Message, decision.Payload)
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
		s.incomingGlobalRequests = make(map[uint64]struct{})
		s.channels = make(map[uint64]*Channel)
		s.peerChannelIDs = make(map[uint64]uint64)
		s.activeChannels = 0
		s.pendingOpens = 0
		s.pendingChannelRequests = 0
		s.mu.Unlock()

		if _, ok := err.(*protocolError); ok {
			_ = s.sendEnvelopeAsync(&sessionpb.Envelope{
				Kind: &sessionpb.Envelope_Disconnect{
					Disconnect: &sessionpb.Disconnect{
						Code:    "protocol-error",
						Message: "protocol error",
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
	if s.stopParent != nil {
		s.stopParent()
	}
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
