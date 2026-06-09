package transport

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/Mikadore/mygosh/lib/bincoder"
	"github.com/rotisserie/eris"
)

const TRANSPORT_KEYPAIR_ALGO string = "x25519"

// Identity keypair
type Keypair struct {
	Algorithm string
	Public    [32]byte
	Private   [32]byte
	Comment   string
}

func GenerateKeypair() (Keypair, error) {
	key, err := NOISE_DH.GenerateKeypair(rand.Reader)
	if err != nil {
		return Keypair{}, err
	}

	if len(key.Private) != 32 || len(key.Public) != 32 {
		panic("x25519 key length is not 32")
	}

	return Keypair{
		Algorithm: TRANSPORT_KEYPAIR_ALGO,
		Public:    [32]byte(key.Public),
		Private:   [32]byte(key.Private),
	}, nil
}

func (k *Keypair) ByteEncode() []byte {
	w := bincoder.NewEncoder()
	w.Write([]byte("mygosh-ident-keypair"))
	w.UTF8String(k.Algorithm)
	w.Write(k.Public[:])
	w.Write(k.Private[:])
	w.UTF8String(k.Comment)
	if w.Err() != nil {
		panic(eris.Wrap(w.Err(), "This encode must not fail"))
	}
	return w.Result()
}

