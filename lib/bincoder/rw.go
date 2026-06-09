package bincoder

import (
	"encoding/binary"
	"io"
	"math"

	"github.com/rotisserie/eris"
)

var ORDER binary.ByteOrder = binary.BigEndian

// Always does a `io.ReadFull` of 4 bytes and returns a `uint32`
func ReadU32(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err

	}
	return ORDER.Uint32(buf[:]), nil
}

func WriteU32(w io.Writer, num uint32) error {
	var buf [4]byte
	ORDER.PutUint32(buf[:], num)
	return writeFull(w, buf[:])
}

// `maxBytes` restricts the maximum allowed read size.
// Passing 0 means there is no restriction on the possible
// read size
func ReadBytes(r io.Reader, maxBytes int) ([]byte, error) {
	len, err := ReadU32(r)
	if err != nil {
		return nil, err
	}
	if (maxBytes != 0) && len > uint32(maxBytes) {
		return nil, eris.Errorf("length %v exceeds maximum %v", len, maxBytes)
	}
	buf := make([]byte, len)
	_, err = io.ReadFull(r, buf)
	return buf, err
}

func WriteBytes(w io.Writer, b []byte) error {
	if uint64(len(b)) > math.MaxUint32 {
		return eris.Errorf("chunk size exceeds length field width: %v", len(b))
	}
	err := WriteU32(w, uint32(len(b)))
	if err != nil {
		return err
	}
	return writeFull(w, b)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
