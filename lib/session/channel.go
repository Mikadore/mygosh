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
	errSessionNotRunning = eris.New("session not running")
	errSessionRunStarted = eris.New("session run already started")
	errChannelClosed     = eris.New("channel closed")
	errChannelWriteEOF   = eris.New("channel write side closed")
)

type channelWaitResult struct {
	response *ChannelResponse
	err      error
}

type Channel struct {
	sess *Session

	id     uint64
	peerID uint64
	typ    string

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
}

func newPendingChannel(sess *Session, localID uint64, typ string) *Channel {
	return &Channel{
		sess:            sess,
		id:              localID,
		typ:             typ,
		openWait:        make(chan error, 1),
		pendingRequests: make(map[uint64]chan channelWaitResult),
		handler:         normalizeChannelHandler(nil),
		stateCh:         make(chan struct{}),
	}
}

func newIncomingChannel(sess *Session, localID uint64, peerID uint64, typ string, remoteWindow uint32, maxRemotePacket uint32, handler ChannelHandler) *Channel {
	return &Channel{
		sess:               sess,
		id:                 localID,
		peerID:             peerID,
		typ:                typ,
		openConfirmed:      true,
		localWindow:        sess.config.InitialWindow,
		remoteWindow:       remoteWindow,
		maxLocalPacket:     sess.config.MaxPacketSize,
		maxRemotePacket:    maxRemotePacket,
		pendingRequests:    make(map[uint64]chan channelWaitResult),
		handler:            normalizeChannelHandler(handler),
		stateCh:            make(chan struct{}),
		pendingWindowBytes: 0,
	}
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

			return ch.sess.sendEnvelope(&sessionpb.Envelope{
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
		case <-ch.sess.closed:
			return ch.sess.closeCause()
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
				if err := ch.sess.sendEnvelope(&sessionpb.Envelope{
					Kind: &sessionpb.Envelope_ChannelWindowAdjust{
						ChannelWindowAdjust: &sessionpb.ChannelWindowAdjust{
							RecipientChannelId: peerID,
							BytesToAdd:         adjust,
						},
					},
				}); err != nil {
					ch.sess.closeWithCause(eris.Wrap(err, "send channel window adjust"))
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
			return nil, err
		}

		waitCh := ch.stateCh
		ch.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ch.sess.closed:
			return nil, ch.sess.closeCause()
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

	err := ch.sess.sendEnvelope(&sessionpb.Envelope{
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
	case <-ch.sess.closed:
		return nil, ch.sess.closeCause()
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

	return ch.sess.sendEnvelope(&sessionpb.Envelope{
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
	ch.mu.Unlock()

	if shouldRemove {
		defer ch.sess.removeChannel(ch.id)
	}
	if !openConfirmed {
		return nil
	}

	return ch.sess.sendEnvelope(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ChannelClose{
			ChannelClose: &sessionpb.ChannelClose{RecipientChannelId: peerID},
		},
	})
}

func (ch *Channel) channelErrorLocked() error {
	if ch.sessionErr != nil {
		return ch.sessionErr
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
}

func (ch *Channel) shutdown(err error) {
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
	ch.mu.Unlock()
}
