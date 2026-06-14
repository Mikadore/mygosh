package transport

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/charmbracelet/log"
	"github.com/flynn/noise"
	"github.com/rotisserie/eris"
)

const MaxPayloadSize = 32 * 1024

type Transport struct {
	conn           net.Conn
	writeMu        sync.Mutex
	tx             *noise.CipherState
	tx_mux         sync.Mutex
	rx             *noise.CipherState
	rx_mux         sync.Mutex
	channelBinding []byte
}

func (t *Transport) ReceiveFrame() ([]byte, error) {
	t.rx_mux.Lock()
	defer t.rx_mux.Unlock()

	frame, err := t.recvChunk()
	if err != nil {
		return nil, eris.Wrap(err, "failed to receive frame")
	}
	return t.rx.Decrypt(nil, nil, frame)
}

func (t *Transport) SendFrame(p []byte) error {
	t.tx_mux.Lock()
	defer t.tx_mux.Unlock()

	frame, err := t.tx.Encrypt(nil, nil, p)
	if err != nil {
		return eris.Wrap(err, "failed to encrypt frame")
	}
	return eris.Wrap(t.sendChunk(frame), "failed to send frame")
}

func (t *Transport) setCipherStates(first *noise.CipherState, second *noise.CipherState, initiator bool) {
	if initiator {
		t.tx = first
		t.rx = second
		return
	}

	t.tx = second
	t.rx = first
}

func (t *Transport) sendChunk(payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return eris.Errorf("wire: payload too large: %d bytes", len(payload))
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	return eris.Wrapf(bincoder.WriteBytes(t.conn, payload), "send frame (%d bytes)", len(payload))
}

func (t *Transport) recvChunk() ([]byte, error) {
	return bincoder.ReadBytes(t.conn, MaxPayloadSize)
}

func (t *Transport) Close() error {
	return t.conn.Close()
}

func (t *Transport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *Transport) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

func (t *Transport) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

func (t *Transport) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

func (t *Transport) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

func HandshakeClient(conn net.Conn) (*Transport, error) {
	config, err := createConfig(true)
	if err != nil {
		return nil, err
	}
	return handshake(conn, config)
}

func HandshakeServer(conn net.Conn) (*Transport, error) {
	config, err := createConfig(false)
	if err != nil {
		return nil, err
	}
	return handshake(conn, config)
}

func handshake(conn net.Conn, config noise.Config) (*Transport, error) {
	t := Transport{conn: conn}
	state, err := noise.NewHandshakeState(config)
	if err != nil {
		return &t, eris.Wrap(err, "Failed to create noise handshake state")
	}

	log.Info("running handshake", "initiator", config.Initiator)

	// If not initiating, first read from conn then write
	shouldWrite := 1
	if config.Initiator {
		// as initiator, write first then read
		shouldWrite = 0
	}

	for msg_seq := 0; ; msg_seq += 1 {

		if msg_seq%2 == shouldWrite {
			msg, first, second, err := state.WriteMessage(nil, nil)
			if err != nil {
				return &t, eris.Wrap(err, "Handshake error")
			}

			if err := t.sendChunk(msg); err != nil {
				return &t, eris.Wrapf(err, "failed to send handshake message %v", state.MessageIndex())
			}

			if first != nil && second != nil {
				t.setCipherStates(first, second, config.Initiator)
				t.channelBinding = append([]byte(nil), state.ChannelBinding()...)
				break
			}
		} else {
			wireMsg, err := t.recvChunk()
			if err != nil {
				return &t, eris.Wrapf(err, "failed to receive handshake message %v", state.MessageIndex())
			}

			_, first, second, err := state.ReadMessage(nil, wireMsg)
			if err != nil {
				return &t, eris.Wrap(err, "Handshake error")
			}

			if first != nil && second != nil {
				t.setCipherStates(first, second, config.Initiator)
				t.channelBinding = append([]byte(nil), state.ChannelBinding()...)
				break
			}
		}
	}

	if len(t.channelBinding) == 0 {
		return &t, eris.New("noise handshake did not yield a channel binding")
	}

	return &t, nil
}

func createConfig(initiator bool) (noise.Config, error) {
	cs := NOISE_CIPHERSUITE

	prologue := bytes.Join([][]byte{
		[]byte(MYGOSH_NOISE_MAGIC),
		[]byte(MYGOSH_NOISE_VERSION),
		[]byte(MYGOSH_NOISE_PATTERN),
		cs.Name(),
	}, []byte(" "))

	config := noise.Config{
		CipherSuite: cs,
		Pattern:     noise.HandshakeNN,
		Prologue:    prologue,
		Initiator:   initiator,
	}

	return config, nil
}

func (t *Transport) ChannelBinding() []byte {
	if len(t.channelBinding) == 0 {
		return nil
	}
	return append([]byte(nil), t.channelBinding...)
}

const MYGOSH_NOISE_MAGIC string = "mygosh"
const MYGOSH_NOISE_VERSION string = "v0"
const MYGOSH_NOISE_PATTERN string = "Noise_NN"
