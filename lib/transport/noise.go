package transport

import (
	"io"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/flynn/noise"
	"github.com/rotisserie/eris"
)

type NoiseStream struct {
	conn   *Framed
	tx     *noise.CipherState
	tx_mux sync.Mutex
	rx     *noise.CipherState
	rx_mux sync.Mutex
}

func (ns *NoiseStream) Receive() ([]byte, error) {
	ns.rx_mux.Lock()
	defer ns.rx_mux.Unlock()

	frame, err := ns.conn.Receive()
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
	return eris.Wrap(ns.conn.Send(frame), "failed to send frame")
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

func Handshake(rw io.ReadWriter, initiator bool) (*NoiseStream, error) {
	var conn NoiseStream

	conn.conn = NewFramed(rw)

	config := createConfig(initiator)
	state, err := noise.NewHandshakeState(config)

	if err != nil {
		return &conn, eris.Wrap(err, "Failed to create noise handshake state")
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
				return &conn, eris.Wrap(err, "Handshake error")
			}

			if err := conn.conn.Send(msg); err != nil {
				return &conn, eris.Wrapf(err, "failed to send handshake message %v", state.MessageIndex())
			}

			if first != nil && second != nil {
				conn.setCipherStates(first, second, initiator)
				break
			}
		} else {
			msg, err := conn.conn.Receive()
			if err != nil {
				return &conn, eris.Wrapf(err, "failed to receive handshake message %v", state.MessageIndex())
			}

			msg, first, second, err := state.ReadMessage(nil, msg)
			if err != nil {
				return &conn, eris.Wrap(err, "Handshake error")
			}

			if first != nil && second != nil {
				conn.setCipherStates(first, second, initiator)
				break
			}
		}
	}

	return &conn, nil
}

func createConfig(initiator bool) noise.Config {
	return noise.Config{
		CipherSuite: DH25519_ChaChaPoly_SHA256,
		Pattern:     noise.HandshakeNN,
		Prologue:    []byte(MYGOSH_NOISE_PROLOGUE),
		Initiator:   initiator,
	}
}

const MYGOSH_NOISE_PROLOGUE string = "mygosh v0.1"

var DH25519_ChaChaPoly_SHA256 noise.CipherSuite = noise.NewCipherSuite(
	noise.DH25519,
	noise.CipherChaChaPoly,
	noise.HashSHA256,
)
