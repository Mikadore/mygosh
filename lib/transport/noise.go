package transport

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/charmbracelet/log"
	"github.com/flynn/noise"
	"github.com/rotisserie/eris"
)

const MaxPayloadSize = 32 * 1024

type NoiseStream struct {
	conn          net.Conn
	writeMu       sync.Mutex
	tx            *noise.CipherState
	tx_mux        sync.Mutex
	rx            *noise.CipherState
	rx_mux        sync.Mutex
	PeerStaticKey keys.PublicKey
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

func HandshakeClient(conn net.Conn) (*NoiseStream, error) {
	config, err := createConfig(true, nil)
	if err != nil {
		return nil, err
	}
	stream, err := handshake(conn, config)
	if err != nil {
		return nil, err
	}
	if stream.PeerStaticKey.IsZero() {
		return nil, eris.New("noise handshake did not yield a server static key")
	}
	return stream, nil
}

func HandshakeServer(conn net.Conn, staticKey keys.Keypair) (*NoiseStream, error) {
	config, err := createConfig(false, &staticKey)
	if err != nil {
		return nil, err
	}
	return handshake(conn, config)
}

func handshake(conn net.Conn, config noise.Config) (*NoiseStream, error) {
	ns := NoiseStream{conn: conn}
	state, err := noise.NewHandshakeState(config)
	if err != nil {
		return &ns, eris.Wrap(err, "Failed to create noise handshake state")
	}

	log.Info("running handshake", "initiator", config.Initiator)

	// If not initiating, first read from conn then write
	shouldWrite := 1
	if config.Initiator {
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
				ns.setCipherStates(first, second, config.Initiator)
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
			if err := ns.capturePeerStatic(state); err != nil {
				return &ns, err
			}

			if first != nil && second != nil {
				ns.setCipherStates(first, second, config.Initiator)
				break
			}
		}
	}

	return &ns, nil
}

func createConfig(initiator bool, staticKey *keys.Keypair) (noise.Config, error) {
	cs := NOISE_CIPHERSUITE

	prologue := bytes.Join([][]byte{
		[]byte(MYGOSH_NOISE_MAGIC),
		[]byte(MYGOSH_NOISE_VERSION),
		[]byte(MYGOSH_NOISE_PATTERN),
		cs.Name(),
	}, []byte(" "))

	config := noise.Config{
		CipherSuite: cs,
		Pattern:     noise.HandshakeNX,
		Prologue:    prologue,
		Initiator:   initiator,
	}

	if staticKey != nil {
		if err := staticKey.Validate(); err != nil {
			return noise.Config{}, eris.Wrap(err, "invalid static keypair")
		}
		if staticKey.Algorithm != keys.AlgorithmX25519 {
			return noise.Config{}, eris.Errorf("noise static key must use %s, got %s", keys.AlgorithmX25519, staticKey.Algorithm)
		}
		config.StaticKeypair = noise.DHKey{
			Public:  append([]byte(nil), staticKey.Public[:]...),
			Private: append([]byte(nil), staticKey.Private[:]...),
		}
	}

	return config, nil
}

func (ns *NoiseStream) capturePeerStatic(state *noise.HandshakeState) error {
	peerStatic := state.PeerStatic()
	if len(peerStatic) == 0 {
		return nil
	}

	var public [32]byte
	if len(peerStatic) != len(public) {
		return eris.Errorf("noise peer static key length %d does not match expected length %d", len(peerStatic), len(public))
	}
	copy(public[:], peerStatic)
	ns.PeerStaticKey = keys.PublicKey{
		Algorithm: keys.AlgorithmX25519,
		Bytes:     public,
	}
	return nil
}

const MYGOSH_NOISE_MAGIC string = "mygosh"
const MYGOSH_NOISE_VERSION string = "v0"
const MYGOSH_NOISE_PATTERN string = "Noise_NX"
