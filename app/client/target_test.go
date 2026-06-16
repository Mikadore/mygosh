package client

import "testing"

import "github.com/stretchr/testify/require"

func TestParseConnectTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		raw               string
		wantUsername      string
		wantHost          string
		wantPort          string
		wantDialAddress   string
		wantReferenceHost string
	}{
		{
			name:              "host only",
			raw:               "server.example.test",
			wantHost:          "server.example.test",
			wantDialAddress:   "server.example.test:42022",
			wantReferenceHost: "server.example.test",
		},
		{
			name:              "host and port",
			raw:               "server.example.test:7777",
			wantHost:          "server.example.test",
			wantPort:          "7777",
			wantDialAddress:   "server.example.test:7777",
			wantReferenceHost: "server.example.test",
		},
		{
			name:              "username and host",
			raw:               "alice@server.example.test",
			wantUsername:      "alice",
			wantHost:          "server.example.test",
			wantDialAddress:   "server.example.test:42022",
			wantReferenceHost: "server.example.test",
		},
		{
			name:              "username host and port",
			raw:               "alice@server.example.test:7777",
			wantUsername:      "alice",
			wantHost:          "server.example.test",
			wantPort:          "7777",
			wantDialAddress:   "server.example.test:7777",
			wantReferenceHost: "server.example.test",
		},
		{
			name:              "username and bracketed ipv6 host",
			raw:               "alice@[::1]",
			wantUsername:      "alice",
			wantHost:          "::1",
			wantDialAddress:   "[::1]:42022",
			wantReferenceHost: "::1",
		},
		{
			name:              "username bracketed ipv6 host and port",
			raw:               "alice@[::1]:7777",
			wantUsername:      "alice",
			wantHost:          "::1",
			wantPort:          "7777",
			wantDialAddress:   "[::1]:7777",
			wantReferenceHost: "::1",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseConnectTarget(tt.raw)
			require.NoError(t, err)
			require.Equal(t, tt.wantUsername, got.username)
			require.Equal(t, tt.wantHost, got.host)
			require.Equal(t, tt.wantPort, got.port)
			require.Equal(t, tt.wantDialAddress, got.dialAddress(42022))
			require.Equal(t, tt.wantReferenceHost, got.referenceIdentity())
		})
	}
}

func TestParseConnectTargetRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "empty", raw: "", wantErr: "connect target is required"},
		{name: "missing username", raw: "@server.example.test", wantErr: "connect target username is required"},
		{name: "missing host after username", raw: "alice@", wantErr: "connect target host is required"},
		{name: "missing port", raw: "server.example.test:", wantErr: "connect target port is required"},
		{name: "unterminated bracket", raw: "alice@[::1", wantErr: "unterminated bracketed host"},
		{name: "unexpected trailer", raw: "alice@[::1]suffix", wantErr: "unexpected characters after bracketed host"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseConnectTarget(tt.raw)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
