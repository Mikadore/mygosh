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

type NoiseStream struct {
	conn    net.Conn
	writeMu sync.Mutex
	tx      *noise.CipherState
	tx_mux  sync.Mutex
	rx      *noise.CipherState
	rx_mux  sync.Mutex
}

func (ns *NoiseStream) Receive() ([]byte, error) {
	ns.rx_mux.Lock()
	defer ns.rx_mux.Unlock()

	frame, err := ns.recvChunk()
	if err != nil {
		return nil, eris.Wrap(err, "failed to receive frame")
	}
	return ns.rx.Decrypt(nil, nil, frame)
}

func (ns *NoiseStream) Send(p []byte) error {
	ns.tx_mux.Lock()
	defer ns.tx_mux.Unlock()

	frame, err := ns.tx.Encrypt(nil, nil, p)
	if err != nil {
		return eris.Wrap(err, "failed to encrypt frame")
	}
	return eris.Wrap(ns.sendChunk(frame), "failed to send frame")
}

func (ns *NoiseStream) setCipherStates(first *noise.CipherState, second *noise.CipherState, initiator bool) {
	if initiator {
		ns.tx = first
		ns.rx = second
		return
	}

	ns.tx = second
	ns.rx = first
}

func (ns *NoiseStream) sendChunk(payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return eris.Errorf("wire: payload too large: %d bytes", len(payload))
	}

	ns.writeMu.Lock()
	defer ns.writeMu.Unlock()

	return eris.Wrapf(bincoder.WriteBytes(ns.conn, payload), "send frame (%d bytes)", len(payload))
}

func (ns *NoiseStream) recvChunk() ([]byte, error) {
	return bincoder.ReadBytes(ns.conn, MaxPayloadSize)
}

func (ns *NoiseStream) Close() error {
	return ns.conn.Close()
}

func (ns *NoiseStream) LocalAddr() net.Addr {
	return ns.conn.LocalAddr()
}

func (ns *NoiseStream) RemoteAddr() net.Addr {
	return ns.conn.RemoteAddr()
}

func (ns *NoiseStream) SetDeadline(t time.Time) error {
	return ns.conn.SetDeadline(t)
}

func (ns *NoiseStream) SetReadDeadline(t time.Time) error {
	return ns.conn.SetReadDeadline(t)
}

func (ns *NoiseStream) SetWriteDeadline(t time.Time) error {
	return ns.conn.SetWriteDeadline(t)
}

func Handshake(conn net.Conn, initiator bool) (*NoiseStream, error) {
	var ns NoiseStream

	ns = NoiseStream{
		conn: conn,
	}

	config := CreateConfig(initiator)
	state, err := noise.NewHandshakeState(config)

	if err != nil {
		return &ns, eris.Wrap(err, "Failed to create noise handshake state")
	}

	log.Info("running handshake", "initiator", initiator)

	// If not initiating, first read from conn then write
	shouldWrite := 1
	if initiator {
		// as initiator, write first then read
		shouldWrite = 0
	}

	msg := make([]byte, 0, 256)

	for msg_seq := 0; ; msg_seq += 1 {

		if msg_seq%2 == shouldWrite {
			msg, first, second, err := state.WriteMessage(msg[:0], nil)
			if err != nil {
				return &ns, eris.Wrap(err, "Handshake error")
			}

			if err := ns.sendChunk(msg); err != nil {
				return &ns, eris.Wrapf(err, "failed to send handshake message %v", state.MessageIndex())
			}

			if first != nil && second != nil {
				ns.setCipherStates(first, second, initiator)
				break
			}
		} else {
			msg, err := ns.recvChunk()
			if err != nil {
				return &ns, eris.Wrapf(err, "failed to receive handshake message %v", state.MessageIndex())
			}

			msg, first, second, err := state.ReadMessage(nil, msg)
			if err != nil {
				return &ns, eris.Wrap(err, "Handshake error")
			}

			if first != nil && second != nil {
				ns.setCipherStates(first, second, initiator)
				break
			}
		}
	}

	return &ns, nil
}

func CreateConfig(initiator bool) noise.Config {
	cs := NOISE_CIPHERSUITE

	prologue := bytes.Join([][]byte{
		[]byte(MYGOSH_NOISE_MAGIC),
		[]byte(MYGOSH_NOISE_VERSION),
		[]byte(MYGOSH_NOISE_PATTERN),
		cs.Name(),
	}, []byte(" "))

	return noise.Config{
		CipherSuite: cs,
		Pattern:     noise.HandshakeNN,
		Prologue:    prologue,
		Initiator:   initiator,
	}
}

const MYGOSH_NOISE_MAGIC string = "mygosh"
const MYGOSH_NOISE_VERSION string = "v0"
const MYGOSH_NOISE_PATTERN string = "Noise_NX"
