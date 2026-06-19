package service

import (
	"testing"

	"github.com/Mikadore/mygosh/lib/service/servicepb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPayloadRoundTrips(t *testing.T) {
	tests := []struct {
		name    string
		message proto.Message
		target  proto.Message
	}{
		{
			name:    "pty",
			message: &servicepb.PtyRequest{Term: "xterm-256color", Rows: 24, Cols: 80},
			target:  &servicepb.PtyRequest{},
		},
		{
			name:    "exec",
			message: &servicepb.ExecRequest{Command: "/bin/bash"},
			target:  &servicepb.ExecRequest{},
		},
		{
			name:    "terminal size",
			message: &servicepb.TerminalSize{Rows: 40, Cols: 120},
			target:  &servicepb.TerminalSize{},
		},
		{
			name:    "exit status",
			message: &servicepb.ExitStatus{Code: 0},
			target:  &servicepb.ExitStatus{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := MarshalPayload(tt.message)
			require.NoError(t, err)
			require.NoError(t, UnmarshalPayload(payload, tt.target))
			require.True(t, proto.Equal(tt.message, tt.target))
		})
	}
}

func TestMarshalPayloadRejectsInvalidMessages(t *testing.T) {
	_, err := MarshalPayload(&servicepb.PtyRequest{})
	require.Error(t, err)

	_, err = MarshalPayload(&servicepb.ExecRequest{})
	require.Error(t, err)

	_, err = MarshalPayload(&servicepb.TerminalSize{})
	require.Error(t, err)
}

func TestUnmarshalPayloadRejectsMalformedAndInvalidPayloads(t *testing.T) {
	require.Error(t, UnmarshalPayload([]byte{0xff}, &servicepb.ExecRequest{}))

	payload, err := proto.Marshal(&servicepb.ExecRequest{})
	require.NoError(t, err)
	require.Error(t, UnmarshalPayload(payload, &servicepb.ExecRequest{}))
}
