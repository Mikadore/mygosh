package bincoder

import (
	"bytes"
	"math"

	"github.com/rotisserie/eris"
)

type Encoder struct {
	buf bytes.Buffer
	err error
}

func NewEncoder() *Encoder {
	return &Encoder{}
}

func (e *Encoder) Err() error {
	return e.err
}

func (e *Encoder) Len() int {
	return e.buf.Len()
}

func (e *Encoder) Result() []byte {
	if e.err != nil {
		return nil
	}
	return e.buf.Bytes()
}

func (e *Encoder) Write(b []byte) {
	if e.err != nil {
		return
	}
	_, e.err = e.buf.Write(b)
}

func (e *Encoder) U32(n uint32) {
	if e.err != nil {
		return
	}

	var b [4]byte
	ORDER.PutUint32(b[:], n)
	e.Write(b[:])
}

func (e *Encoder) Bytes(b []byte) {
	if e.err != nil {
		return
	}
	if uint64(len(b)) > math.MaxUint32 {
		e.err = eris.Errorf("byte string length %d exceeds length field width", len(b))
		return
	}

	e.U32(uint32(len(b)))
	e.Write(b)
}

func (e *Encoder) UTF8String(s string) {
	e.Bytes([]byte(s))
}
