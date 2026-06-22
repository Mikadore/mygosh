package trust

import (
	"errors"
	"io"
	"strings"

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

type HostKeyMatch uint8

const (
	HostKeyNoHost HostKeyMatch = iota
	HostKeyMismatch
	HostKeyAccepted
	HostKeyRevoked
)

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

// MatchHostKey applies exact-host matching with revocation taking precedence
// over accepted entries for the same host and key.
func (k *KnownHosts) MatchHostKey(host string, key keys.PublicKey) HostKeyMatch {
	if k == nil {
		return HostKeyNoHost
	}

	hostFound := false
	keyAccepted := false
	for i := range k.entries {
		entry := &k.entries[i]
		if !entry.Match(host) {
			continue
		}
		hostFound = true
		if !entry.HostKey.Equal(key) {
			continue
		}
		if entry.Marker == KnownHostRevoked {
			return HostKeyRevoked
		}
		if entry.Marker == KnownHostEmptyMarker {
			keyAccepted = true
		}
	}
	if keyAccepted {
		return HostKeyAccepted
	}
	if hostFound {
		return HostKeyMismatch
	}
	return HostKeyNoHost
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

		marker, valid := parseMarkerString(markerStr)
		if !valid {
			return nil, eris.Errorf("unsupported marker in known_hosts entry: %q", markerStr)
		}
		if marker == KnownHostCertAuthority {
			return nil, eris.New("known_hosts certificate-authority entries are not supported")
		}
		if err := validateKnownHostPatterns(hosts); err != nil {
			return nil, err
		}

		parsedPublicKey, ok, err := sshEd25519PublicKey(publicKey, comment)
		if err != nil {
			return nil, eris.Wrap(err, "parse known_hosts entry")
		}
		if !ok {
			continue
		}

		entries = append(entries, KnownHostEntry{
			Marker:  marker,
			Hosts:   append([]string(nil), hosts...),
			HostKey: parsedPublicKey.Clone(),
		})
	}

	return &KnownHosts{entries: entries}, nil
}

func validateKnownHostPatterns(hosts []string) error {
	if len(hosts) == 0 {
		return eris.New("known_hosts entry has no host identities")
	}
	for _, host := range hosts {
		switch {
		case host == "":
			return eris.New("known_hosts entry has an empty host identity")
		case strings.HasPrefix(host, "|"):
			return eris.Errorf("hashed known_hosts identity %q is not supported", host)
		case strings.HasPrefix(host, "!"):
			return eris.Errorf("negated known_hosts identity %q is not supported", host)
		case strings.ContainsAny(host, "*?"):
			return eris.Errorf("wildcard known_hosts identity %q is not supported", host)
		case strings.HasPrefix(host, "["):
			return eris.Errorf("host-plus-port known_hosts identity %q is not supported", host)
		case strings.ContainsAny(host, " \t\r\n\x00"):
			return eris.Errorf("invalid known_hosts identity %q", host)
		}
	}
	return nil
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
