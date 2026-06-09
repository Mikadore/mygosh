package bincoder

import (
	"bytes"
	"math"
	"unicode/utf8"

	"github.com/rotisserie/eris"
)


type Decoder struct {
	buf []byte
	off int
	err error

	maxBytes uint32
}

func NewCursor(b []byte) *Decoder {
	return &Decoder{
		buf:      b,
		maxBytes: math.MaxUint32,
	}
}

func (c *Decoder) WithMaxBytes(n uint32) *Decoder {
	c.maxBytes = n
	return c
}

func (c *Decoder) Err() error {
	return c.err
}

func (c *Decoder) Offset() int {
	return c.off
}

func (c *Decoder) Rest() []byte {
	if c.err != nil {
		return nil
	}
	return c.buf[c.off:]
}

func (c *Decoder) Done() error {
	if c.err != nil {
		return c.err
	}
	if c.off != len(c.buf) {
		return eris.Errorf("trailing data: %d bytes remaining at offset %d", len(c.buf)-c.off, c.off)
	}
	return nil
}

func (c *Decoder) Take(n uint32) []byte {
	if c.err != nil {
		return nil
	}

	if uint64(c.off)+uint64(n) > uint64(len(c.buf)) {
		c.err = eris.Errorf("truncated: need %d bytes at offset %d, have %d",
			n, c.off, len(c.buf)-c.off)
		return nil
	}

	start := c.off
	c.off += int(n)
	return c.buf[start:c.off]
}

func (c *Decoder) U32() uint32 {
	b := c.Take(4)
	if c.err != nil {
		return 0
	}
	return ORDER.Uint32(b)
}

func (c *Decoder) Bytes() []byte {
	n := c.U32()
	if c.err != nil {
		return nil
	}
	if n > c.maxBytes {
		c.err = eris.Errorf("byte string length %d exceeds maximum %d", n, c.maxBytes)
		return nil
	}
	return c.Take(n)
}

func (c *Decoder) UTF8String() string {
	b := c.Bytes()
	if c.err != nil {
		return ""
	}
	if !utf8.Valid(b) {
		c.err = eris.Errorf("invalid UTF-8 string at offset %d", c.off-len(b))
		return ""
	}
	return string(b)
}

func (c *Decoder) ExpectBytes(want []byte) {
	got := c.Take(uint32(len(want)))
	if c.err != nil {
		return
	}
	if !bytes.Equal(got, want) {
		c.err = eris.Errorf("unexpected bytes at offset %d", c.off-len(want))
	}
}