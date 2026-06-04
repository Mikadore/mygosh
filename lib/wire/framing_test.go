package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFramedSendPrefixesPayloadLength(t *testing.T) {
	var buf bytes.Buffer
	framed := NewFramed(&buf)

	payload := []byte("hello")
	if err := framed.Send(payload); err != nil {
		t.Fatalf("send frame: %v", err)
	}

	got := buf.Bytes()
	if len(got) != 4+len(payload) {
		t.Fatalf("frame length = %d, want %d", len(got), 4+len(payload))
	}
	if size := binary.BigEndian.Uint32(got[:4]); size != uint32(len(payload)) {
		t.Fatalf("prefix length = %d, want %d", size, len(payload))
	}
	if !bytes.Equal(got[4:], payload) {
		t.Fatalf("payload = %q, want %q", got[4:], payload)
	}
}

func TestFramedReceiveReadsSinglePayload(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello")

	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	buf.Write(prefix[:])
	buf.Write(payload)
	buf.WriteString("trailing")

	got, err := NewFramed(&buf).Receive()
	if err != nil {
		t.Fatalf("receive frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if buf.String() != "trailing" {
		t.Fatalf("remaining bytes = %q, want trailing", buf.String())
	}
}

func TestFramedRoundTripEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	framed := NewFramed(&buf)

	if err := framed.Send(nil); err != nil {
		t.Fatalf("send empty frame: %v", err)
	}
	got, err := framed.Receive()
	if err != nil {
		t.Fatalf("receive empty frame: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("payload length = %d, want 0", len(got))
	}
}
