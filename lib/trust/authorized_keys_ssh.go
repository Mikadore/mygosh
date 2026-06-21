package trust

import (
	"bytes"
	"strings"

	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/rotisserie/eris"
	"golang.org/x/crypto/ssh"
)

type AuthorizedKeyOption struct {
	Name     string
	Value    string
	HasValue bool
}

type AuthorizedKeyEntry struct {
	Options []AuthorizedKeyOption
	Key     keys.PublicKey
}

type AuthorizedKeys struct {
	Entries []AuthorizedKeyEntry
}

func ParseAuthorizedKeys(contents []byte) (AuthorizedKeys, error) {
	contents = bytes.TrimSpace(contents)

	var out AuthorizedKeys
	for len(contents) != 0 {
		pk, comment, options, rest, err := ssh.ParseAuthorizedKey(contents)
		if err != nil {
			return AuthorizedKeys{}, eris.Wrap(err, "parse authorized_keys entry")
		}
		contents = bytes.TrimSpace(rest)

		if pk.Type() != ssh.KeyAlgoED25519 {
			continue
		}

		publicKey, ok, err := sshEd25519PublicKey(pk, comment)
		if err != nil {
			return AuthorizedKeys{}, eris.Wrap(err, "parse authorized_keys entry")
		}
		if !ok {
			continue
		}

		parsedOptions, err := parseAuthorizedKeyOptions(options)
		if err != nil {
			return AuthorizedKeys{}, eris.Wrap(err, "parse authorized_keys options")
		}

		out.Entries = append(out.Entries, AuthorizedKeyEntry{
			Options: parsedOptions,
			Key:     clonePublicKey(publicKey),
		})
	}

	return out, nil
}

func MatchAuthorizedKey(authorized AuthorizedKeys, presented keys.PublicKey) bool {
	for _, entry := range authorized.Entries {
		if entry.Key.Compare(presented) == 0 {
			return true
		}
	}
	return false
}

func parseAuthorizedKeyOptions(options []string) ([]AuthorizedKeyOption, error) {
	parsed := make([]AuthorizedKeyOption, 0, len(options))
	for _, option := range options {
		parsedOption, err := parseAuthorizedKeyOption(option)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, parsedOption)
	}
	return parsed, nil
}

func parseAuthorizedKeyOption(option string) (AuthorizedKeyOption, error) {
	if option == "" {
		return AuthorizedKeyOption{}, eris.New("authorized_keys option is empty")
	}

	name, value, hasValue := strings.Cut(option, "=")
	if name == "" {
		return AuthorizedKeyOption{}, eris.New("authorized_keys option name is empty")
	}

	parsed := AuthorizedKeyOption{
		Name:     name,
		HasValue: hasValue,
	}
	if hasValue {
		parsed.Value = value
	}

	return parsed, nil
}
