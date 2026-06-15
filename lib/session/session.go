package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
	charmlog "github.com/charmbracelet/log"
	"github.com/rotisserie/eris"
)

type Role string

const (
	RoleClient Role = "client"
	RoleServer Role = "server"
)

type ClientConfig struct {
	ReferenceIdentity   string
	Username            string
	ClientIdentity      keys.Keypair
	VerifyServerHostKey auth.HostKeyVerifier
	HandshakeTimeout    time.Duration
	AuthTimeout         time.Duration
	Config              Config
	Logger              *charmlog.Logger
}

type ServerConfig struct {
	HostKey          keys.Keypair
	AuthorizeClient  auth.AuthorizeClientFunc
	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
	Config           Config
	Logger           *charmlog.Logger
}

type Metadata struct {
	ReferenceIdentity string
	ServerHostKey     keys.PublicKey
	ClientIdentity    auth.ClientIdentity
}

type globalWaitResult struct {
	response *GlobalResponse
	err      error
}

type Session struct {
	runtime   *connRuntime
	role      Role
	transport *transport.Transport
	metadata  Metadata
	logger    *charmlog.Logger
	config    Config

	mu                  sync.Mutex
	nextLocalChannelID  uint64
	channels            map[uint64]*Channel
	nextGlobalRequestID uint64
	pendingGlobal       map[uint64]chan globalWaitResult
	runStarted          bool

	writeMu  sync.Mutex
	closed   chan struct{}
	runReady chan struct{}
	once     sync.Once
}

func Connect(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimeouts(cfg.HandshakeTimeout, cfg.AuthTimeout); err != nil {
		return nil, eris.Wrap(err, "validate client session config")
	}
	if err := cfg.Config.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate client session mux config")
	}

	handshakeTimeout := resolveTimeout(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	authTimeout := resolveTimeout(cfg.AuthTimeout, defaultAuthTimeout)
	logger := logging.Resolve(cfg.Logger)
	ctx = logging.IntoContext(ctx, logger)
	logger.Debug("starting session connect", "role", RoleClient, "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := newConnRuntime(ctx, conn, logger)

	var messageTransport *transport.Transport
	err := runtime.runWithTimeout("handshake", handshakeTimeout, func() error {
		var err error
		messageTransport, err = transport.HandshakeClientWithLogger(conn, logger)
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.setTarget(messageTransport)
	logger.Debug("noise transport established", "role", RoleClient, "remote", remoteAddrString(conn))

	var result auth.Result
	err = runtime.runWithTimeout("auth", authTimeout, func() error {
		var err error
		result, err = auth.AuthenticateClient(messageTransport, messageTransport.ChannelBinding(), auth.ClientConfig{
			ReferenceIdentity:   cfg.ReferenceIdentity,
			Username:            cfg.Username,
			ClientIdentity:      cfg.ClientIdentity,
			VerifyServerHostKey: cfg.VerifyServerHostKey,
			Logger:              logger,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "authenticate client")
		_ = runtime.Close()
		return nil, wrapped
	}
	logger.Debug("session connect authenticated", "role", RoleClient, "reference_identity", result.ReferenceIdentity, "server_fingerprint", result.ServerHostKey.FingerprintSHA256())

	return newSession(runtime, RoleClient, messageTransport, metadataFromAuthResult(result), cfg.Config, logger), nil
}

func Accept(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimeouts(cfg.HandshakeTimeout, cfg.AuthTimeout); err != nil {
		return nil, eris.Wrap(err, "validate server session config")
	}
	if err := cfg.Config.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate server session mux config")
	}

	handshakeTimeout := resolveTimeout(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	authTimeout := resolveTimeout(cfg.AuthTimeout, defaultAuthTimeout)
	logger := logging.Resolve(cfg.Logger)
	ctx = logging.IntoContext(ctx, logger)
	logger.Debug("starting session accept", "role", RoleServer, "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := newConnRuntime(ctx, conn, logger)

	var messageTransport *transport.Transport
	err := runtime.runWithTimeout("handshake", handshakeTimeout, func() error {
		var err error
		messageTransport, err = transport.HandshakeServerWithLogger(conn, logger)
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.setTarget(messageTransport)
	logger.Debug("noise transport established", "role", RoleServer, "remote", remoteAddrString(conn))

	var result auth.Result
	err = runtime.runWithTimeout("auth", authTimeout, func() error {
		var err error
		result, err = auth.AuthenticateServer(messageTransport, messageTransport.ChannelBinding(), auth.ServerConfig{
			HostKey:         cfg.HostKey,
			AuthorizeClient: cfg.AuthorizeClient,
			Logger:          logger,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "authenticate server")
		_ = runtime.Close()
		return nil, wrapped
	}
	logger.Debug("session accept authenticated", "role", RoleServer, "reference_identity", result.ReferenceIdentity, "username", result.ClientIdentity.Username, "client_fingerprint", result.ClientIdentity.PublicKey.FingerprintSHA256())

	return newSession(runtime, RoleServer, messageTransport, metadataFromAuthResult(result), cfg.Config, logger), nil
}

func EstablishClient(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Session, error) {
	return Connect(ctx, conn, cfg)
}

func EstablishServer(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Session, error) {
	return Accept(ctx, conn, cfg)
}

func newSession(runtime *connRuntime, role Role, messageTransport *transport.Transport, metadata Metadata, cfg Config, logger *charmlog.Logger) *Session {
	cfg = cfg.withDefaults()

	s := &Session{
		runtime:       runtime,
		role:          role,
		transport:     messageTransport,
		metadata:      metadata,
		logger:        logging.Resolve(logger),
		config:        cfg,
		channels:      make(map[uint64]*Channel),
		pendingGlobal: make(map[uint64]chan globalWaitResult),
		closed:        make(chan struct{}),
		runReady:      make(chan struct{}),
	}

	go func() {
		<-runtime.ctx.Done()
		s.shutdown(context.Cause(runtime.ctx))
	}()

	return s
}

func (s *Session) Role() Role {
	return s.role
}

func (s *Session) Metadata() Metadata {
	return cloneMetadata(s.metadata)
}

func (s *Session) Run(ctx context.Context, handler Handler) error {
	ctx = normalizeContext(ctx)

	s.mu.Lock()
	if s.runStarted {
		s.mu.Unlock()
		return errSessionRunStarted
	}
	s.runStarted = true
	s.mu.Unlock()

	handler = normalizeHandler(handler)
	logger := logging.Resolve(s.logger)
	logger.Debug("session run loop started", "role", s.role, "reference_identity", s.metadata.ReferenceIdentity)

	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	stopCh := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			s.closeWithCause(context.Cause(runCtx))
		case <-stopCh:
		}
	}()
	defer close(stopCh)

	var finalErr error
	defer func() {
		if finalErr != nil {
			s.closeWithCause(finalErr)
		} else {
			_ = s.runtime.Close()
		}

		disconnectCtx := context.WithoutCancel(runCtx)
		handler.OnDisconnect(disconnectCtx, finalErr)
	}()

	close(s.runReady)

	for {
		var frame sessionpb.Envelope
		if err := transport.ReceiveProto(s.transport, &frame); err != nil {
			if eris.Is(err, io.EOF) {
				logger.Debug("session stream closed", "role", s.role)
				finalErr = nil
				return nil
			}
			if cause := context.Cause(s.runtime.ctx); cause != nil {
				finalErr = cause
				return cause
			}
			if runErr := runCtx.Err(); runErr != nil {
				finalErr = runErr
				return runErr
			}
			finalErr = eris.Wrap(err, "receive session frame")
			return finalErr
		}

		if err := s.handleEnvelope(runCtx, handler, &frame); err != nil {
			finalErr = err
			return err
		}
	}
}

func (s *Session) OpenChannel(ctx context.Context, typ string, payload []byte) (*Channel, error) {
	ctx = normalizeContext(ctx)
	if typ == "" {
		return nil, eris.New("channel type is required")
	}
	if err := s.ensureRunning(); err != nil {
		return nil, err
	}

	payload = cloneBytes(payload)

	s.mu.Lock()
	localID := s.nextLocalChannelID
	s.nextLocalChannelID++

	ch := newPendingChannel(s, localID, typ)
	s.channels[localID] = ch
	s.mu.Unlock()

	waitCh := ch.openWait

	err := s.sendEnvelope(&sessionpb.Envelope{
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
	case <-s.closed:
		return nil, s.closeCause()
	}
}

func (s *Session) SendGlobalRequest(ctx context.Context, typ string, payload []byte, wantReply bool) (*GlobalResponse, error) {
	ctx = normalizeContext(ctx)
	if typ == "" {
		return nil, eris.New("global request type is required")
	}
	if err := s.ensureRunning(); err != nil {
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

	err := s.sendEnvelope(&sessionpb.Envelope{
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
	case <-s.closed:
		return nil, s.closeCause()
	}
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	if s.runtime != nil {
		return s.runtime.Close()
	}
	if s.transport != nil {
		return s.transport.Close()
	}
	return nil
}

func (s *Session) handleEnvelope(ctx context.Context, handler Handler, frame *sessionpb.Envelope) error {
	switch kind := frame.GetKind().(type) {
	case *sessionpb.Envelope_ChannelOpen:
		return s.handleChannelOpen(ctx, handler, kind.ChannelOpen)
	case *sessionpb.Envelope_ChannelOpenResult:
		return s.handleChannelOpenResult(kind.ChannelOpenResult)
	case *sessionpb.Envelope_ChannelData:
		return s.handleChannelData(kind.ChannelData)
	case *sessionpb.Envelope_ChannelWindowAdjust:
		return s.handleChannelWindowAdjust(kind.ChannelWindowAdjust)
	case *sessionpb.Envelope_ChannelEof:
		return s.handleChannelEOF(ctx, kind.ChannelEof)
	case *sessionpb.Envelope_ChannelClose:
		return s.handleChannelClose(ctx, kind.ChannelClose)
	case *sessionpb.Envelope_ChannelRequest:
		return s.handleChannelRequest(ctx, kind.ChannelRequest)
	case *sessionpb.Envelope_ChannelResult:
		return s.handleChannelResult(kind.ChannelResult)
	case *sessionpb.Envelope_GlobalRequest:
		return s.handleGlobalRequest(ctx, handler, kind.GlobalRequest)
	case *sessionpb.Envelope_GlobalResult:
		return s.handleGlobalResult(kind.GlobalResult)
	case *sessionpb.Envelope_Disconnect:
		return s.handleDisconnect(kind.Disconnect)
	default:
		return s.protocolErrorf("unsupported session frame %T", frame.GetKind())
	}
}

func (s *Session) handleChannelOpen(ctx context.Context, handler Handler, msg *sessionpb.ChannelOpen) error {
	localID := s.reserveLocalChannelID()
	ch := newIncomingChannel(s, localID, msg.GetSenderChannelId(), msg.GetChannelType(), msg.GetInitialWindow(), msg.GetMaxPacketSize(), nil)

	decision := handler.OnChannelOpen(ctx, ch, ChannelOpenRequest{
		Type:          msg.GetChannelType(),
		Payload:       cloneBytes(msg.GetPayload()),
		InitialWindow: msg.GetInitialWindow(),
		MaxPacketSize: msg.GetMaxPacketSize(),
	})
	if !decision.OK {
		return s.sendEnvelope(&sessionpb.Envelope{
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
	s.mu.Unlock()

	return s.sendEnvelope(&sessionpb.Envelope{
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
	var remove bool

	ch.mu.Lock()
	if ch.openConfirmed || ch.openWait == nil {
		ch.mu.Unlock()
		return s.protocolErrorf("received duplicate channel open result for channel %d", msg.GetRecipientChannelId())
	}
	openWait = ch.openWait
	ch.openWait = nil

	switch result := msg.GetResult().(type) {
	case *sessionpb.ChannelOpenResult_Success:
		ch.openConfirmed = true
		ch.peerID = result.Success.GetSenderChannelId()
		ch.localWindow = s.config.InitialWindow
		ch.remoteWindow = result.Success.GetInitialWindow()
		ch.maxLocalPacket = s.config.MaxPacketSize
		ch.maxRemotePacket = result.Success.GetMaxPacketSize()
		ch.signalLocked()
		autoClose = ch.openCanceled
	case *sessionpb.ChannelOpenResult_Reject:
		remove = true
		ch.signalLocked()
		select {
		case openWait <- eris.Errorf("channel open rejected: %s", result.Reject.GetMessage()):
		default:
		}
		ch.mu.Unlock()
		if remove {
			s.removeChannel(ch.id)
		}
		return nil
	default:
		ch.mu.Unlock()
		return s.protocolErrorf("received invalid channel open result for channel %d", msg.GetRecipientChannelId())
	}
	ch.mu.Unlock()

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

func (s *Session) handleChannelEOF(ctx context.Context, msg *sessionpb.ChannelEof) error {
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel EOF for unknown channel %d", msg.GetRecipientChannelId())
	}

	ch.mu.Lock()
	if ch.closeSent || ch.closeReceived {
		ch.mu.Unlock()
		return s.protocolErrorf("received channel EOF after channel %d was closed", ch.id)
	}
	if ch.eofReceived {
		ch.mu.Unlock()
		return nil
	}
	ch.eofReceived = true
	ch.signalLocked()
	handler := ch.handler
	ch.mu.Unlock()

	handler.OnEOF(ctx, ch)
	return nil
}

func (s *Session) handleChannelClose(ctx context.Context, msg *sessionpb.ChannelClose) error {
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel close for unknown channel %d", msg.GetRecipientChannelId())
	}

	ch.mu.Lock()
	if ch.closeReceived {
		ch.mu.Unlock()
		return nil
	}
	ch.closeReceived = true
	ch.signalLocked()
	handler := ch.handler
	shouldRemove := ch.closeSent
	ch.mu.Unlock()

	handler.OnClose(ctx, ch)
	if shouldRemove {
		s.removeChannel(ch.id)
	}
	return nil
}

func (s *Session) handleChannelRequest(ctx context.Context, msg *sessionpb.ChannelRequest) error {
	ch := s.lookupChannel(msg.GetRecipientChannelId())
	if ch == nil {
		return s.protocolErrorf("received channel request for unknown channel %d", msg.GetRecipientChannelId())
	}

	ch.mu.Lock()
	if ch.closeSent || ch.closeReceived {
		ch.mu.Unlock()
		return s.protocolErrorf("received channel request for closed channel %d", ch.id)
	}
	handler := ch.handler
	peerID := ch.peerID
	ch.mu.Unlock()

	response := handler.OnRequest(ctx, ch, ChannelRequest{
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

	return s.sendEnvelope(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelResult{ChannelResult: result},
	})
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

func (s *Session) handleGlobalRequest(ctx context.Context, handler Handler, msg *sessionpb.GlobalRequest) error {
	response := handler.OnGlobalRequest(ctx, GlobalRequest{
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

	return s.sendEnvelope(&sessionpb.Envelope{
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

func (s *Session) ensureRunning() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.runStarted {
		return errSessionNotRunning
	}
	return nil
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
	delete(s.channels, id)
}

func (s *Session) sendEnvelope(frame *sessionpb.Envelope) error {
	if frame == nil {
		return eris.New("session envelope is required")
	}
	if cause := context.Cause(s.runtime.ctx); cause != nil {
		return cause
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if cause := context.Cause(s.runtime.ctx); cause != nil {
		return cause
	}

	if err := transport.SendProto(s.transport, frame); err != nil {
		if cause := context.Cause(s.runtime.ctx); cause != nil {
			return cause
		}
		return eris.Wrap(err, "send session envelope")
	}
	return nil
}

func (s *Session) protocolErrorf(format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	_ = s.sendEnvelope(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_Disconnect{
			Disconnect: &sessionpb.Disconnect{
				Code:    "protocol-error",
				Message: message,
			},
		},
	})
	return eris.New(message)
}

func (s *Session) closeWithCause(cause error) {
	if s == nil || s.runtime == nil {
		return
	}
	_ = s.runtime.fail(cause)
}

func (s *Session) closeCause() error {
	if s == nil || s.runtime == nil {
		return context.Canceled
	}
	if cause := context.Cause(s.runtime.ctx); cause != nil {
		return cause
	}
	return context.Canceled
}

func (s *Session) shutdown(err error) {
	if err == nil {
		err = context.Canceled
	}

	s.once.Do(func() {
		s.mu.Lock()
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
		close(s.closed)
		s.mu.Unlock()

		for _, ch := range channels {
			ch.shutdown(err)
		}
		for _, waitCh := range pendingGlobal {
			select {
			case waitCh <- globalWaitResult{err: err}:
			default:
			}
		}
	})
}

func metadataFromAuthResult(result auth.Result) Metadata {
	return Metadata{
		ReferenceIdentity: result.ReferenceIdentity,
		ServerHostKey:     clonePublicKey(result.ServerHostKey),
		ClientIdentity:    cloneClientIdentity(result.ClientIdentity),
	}
}

func cloneMetadata(meta Metadata) Metadata {
	return Metadata{
		ReferenceIdentity: meta.ReferenceIdentity,
		ServerHostKey:     clonePublicKey(meta.ServerHostKey),
		ClientIdentity:    cloneClientIdentity(meta.ClientIdentity),
	}
}

func cloneClientIdentity(identity auth.ClientIdentity) auth.ClientIdentity {
	return auth.ClientIdentity{
		Username:  identity.Username,
		PublicKey: clonePublicKey(identity.PublicKey),
	}
}

func clonePublicKey(key keys.PublicKey) keys.PublicKey {
	return keys.PublicKey{
		Algorithm: key.Algorithm,
		Bytes:     append([]byte(nil), key.Bytes...),
		Comment:   key.Comment,
	}
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

func validateTimeouts(handshakeTimeout time.Duration, authTimeout time.Duration) error {
	if handshakeTimeout < 0 {
		return eris.New("handshake timeout must not be negative")
	}
	if authTimeout < 0 {
		return eris.New("auth timeout must not be negative")
	}
	return nil
}

func remoteAddrString(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}
