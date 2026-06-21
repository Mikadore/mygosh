package trust

import (
	"errors"
	"io"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/rotisserie/eris"
	"github.com/samber/lo"
	"golang.org/x/crypto/ssh"
)

type KnownHostMarker int

const (
	KnownHostEmptyMarker KnownHostMarker = iota
	KnownHostCertAuthority
	KnownHostRevoked
)

const (
	markerStringEmpty         = ""
	markerStringCertAuthority = "cert-authority"
	markerStringRevoked       = "revoked"
)

func MarkerIsValid(marker KnownHostMarker) bool {
	return marker >= KnownHostEmptyMarker && marker <= KnownHostRevoked
}

type KnownHostEntry struct {
	Marker  KnownHostMarker
	Hosts   []string
	HostKey keys.PublicKey
}

func (k *KnownHostEntry) ValidMarker() bool {
	return k != nil && MarkerIsValid(k.Marker)
}

func (k *KnownHostEntry) Match(host string) bool {
	return k != nil && lo.Contains(k.Hosts, host)
}

func (k *KnownHostEntry) MatchesValid(host string) bool {
	return k.ValidMarker() && k.Marker != KnownHostRevoked && k.Match(host)
}

type KnownHosts struct {
	entries []KnownHostEntry
}

type KnownHostsMatchCallback func(*KnownHostEntry) bool

func (k *KnownHosts) Match(policy KnownHostsMatchCallback) (*KnownHostEntry, bool) {
	if k == nil || policy == nil {
		return nil, false
	}

	for i := range k.entries {
		entry := &k.entries[i]
		if policy(entry) {
			return entry, true
		}
	}

	return nil, false
}

func ParseKnownHosts(contents []byte) (*KnownHosts, error) {
	entries := make([]KnownHostEntry, 0, 32)

	for len(contents) != 0 {
		markerStr, hosts, publicKey, comment, rest, err := ssh.ParseKnownHosts(contents)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, eris.Wrap(err, "parse known_hosts entry")
		}
		contents = rest

		parsedPublicKey, ok, err := sshEd25519PublicKey(publicKey, comment)
		if err != nil {
			return nil, eris.Wrap(err, "parse known_hosts entry")
		}
		if !ok {
			continue
		}

		marker, valid := parseMarkerString(markerStr)
		if !valid {
			return nil, eris.Errorf("invalid marker in known_hosts entry: %q", markerStr)
		}

		entries = append(entries, KnownHostEntry{
			Marker:  marker,
			Hosts:   append([]string(nil), hosts...),
			HostKey: parsedPublicKey.Clone(),
		})
	}

	return &KnownHosts{entries: entries}, nil
}

func parseMarkerString(marker string) (KnownHostMarker, bool) {
	switch marker {
	case markerStringEmpty:
		return KnownHostEmptyMarker, true
	case markerStringCertAuthority:
		return KnownHostCertAuthority, true
	case markerStringRevoked:
		return KnownHostRevoked, true
	default:
		return -1, false
	}
}
