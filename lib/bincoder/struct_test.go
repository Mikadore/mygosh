package bincoder

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalizeEncodesFieldsInDeclarationOrder(t *testing.T) {
	type payload struct {
		Flag    bool
		Code    byte
		Count   uint32
		Name    string
		Payload []byte
	}

	got, err := Canonicalize(&payload{
		Flag:    true,
		Code:    0xab,
		Count:   42,
		Name:    "hello",
		Payload: []byte{0x00, 0xff, '\n'},
	})
	require.NoError(t, err)

	dec := NewCursor(got)
	require.True(t, dec.Bool())
	require.Equal(t, byte(0xab), dec.Byte())
	require.Equal(t, uint32(42), dec.U32())
	require.Equal(t, []byte("hello"), dec.Bytes())
	require.Equal(t, []byte{0x00, 0xff, '\n'}, dec.Bytes())
	require.NoError(t, dec.Done())
}

func TestCanonicalizeRejectsUnexportedFields(t *testing.T) {
	type payload struct {
		Visible uint32
		secret  uint32
	}

	_, err := Canonicalize(payload{Visible: 1, secret: 2})
	require.ErrorContains(t, err, `canonicalize field "secret": unexported fields are not supported`)
}

func TestCanonicalizeRejectsStructFields(t *testing.T) {
	type nested struct {
		Count uint32
	}
	type payload struct {
		Nested nested
	}

	_, err := Canonicalize(payload{Nested: nested{Count: 7}})
	require.ErrorContains(t, err, `canonicalize field "Nested": struct type`)
	require.ErrorContains(t, err, "is not supported")
}

func TestCanonicalizeRejectsUnsupportedFields(t *testing.T) {
	type payload struct {
		Count int
	}

	_, err := Canonicalize(payload{Count: 7})
	require.ErrorContains(t, err, `canonicalize field "Count": unsupported type int`)
}

func TestCanonicalizeRejectsNonStructInput(t *testing.T) {
	_, err := Canonicalize(uint32(7))
	require.ErrorContains(t, err, "canonicalize expects a struct or pointer to struct")
}
