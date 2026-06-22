package trust

import (
	"bytes"
	"strconv"
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

type AuthorizedKeyConstraints struct {
	ForcedCommand string
	NoPTY         bool
	Restricted    bool
}

func (e *AuthorizedKeyEntry) Constraints() (AuthorizedKeyConstraints, error) {
	if e == nil {
		return AuthorizedKeyConstraints{}, eris.New("authorized_keys entry is required")
	}
	return parseAuthorizedKeyConstraints(e.Options)
}

type AuthorizedKeys struct {
	entries []AuthorizedKeyEntry
}

type AuthorizedKeyCallback func(*AuthorizedKeyEntry) bool

func (k *AuthorizedKeys) Match(policy AuthorizedKeyCallback) (*AuthorizedKeyEntry, bool) {
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

func ParseAuthorizedKeys(contents []byte) (*AuthorizedKeys, error) {
	contents = bytes.TrimSpace(contents)

	out := &AuthorizedKeys{}
	for len(contents) != 0 {
		pk, comment, options, rest, err := ssh.ParseAuthorizedKey(contents)
		if err != nil {
			return nil, eris.Wrap(err, "parse authorized_keys entry")
		}
		contents = bytes.TrimSpace(rest)

		if pk.Type() != ssh.KeyAlgoED25519 {
			continue
		}

		publicKey, ok, err := sshEd25519PublicKey(pk, comment)
		if err != nil {
			return nil, eris.Wrap(err, "parse authorized_keys entry")
		}
		if !ok {
			continue
		}

		parsedOptions, err := parseAuthorizedKeyOptions(options)
		if err != nil {
			return nil, eris.Wrap(err, "parse authorized_keys options")
		}
		if _, err := parseAuthorizedKeyConstraints(parsedOptions); err != nil {
			return nil, eris.Wrap(err, "validate authorized_keys options")
		}

		out.entries = append(out.entries, AuthorizedKeyEntry{
			Options: parsedOptions,
			Key:     publicKey.Clone(),
		})
	}

	return out, nil
}

func parseAuthorizedKeyConstraints(options []AuthorizedKeyOption) (AuthorizedKeyConstraints, error) {
	var constraints AuthorizedKeyConstraints
	seen := make(map[string]struct{}, len(options))
	for _, option := range options {
		if _, ok := seen[option.Name]; ok {
			return AuthorizedKeyConstraints{}, eris.Errorf("duplicate authorized_keys option %q", option.Name)
		}
		seen[option.Name] = struct{}{}

		switch option.Name {
		case "command":
			if !option.HasValue {
				return AuthorizedKeyConstraints{}, eris.New("authorized_keys command option requires a value")
			}
			command, err := strconv.Unquote(option.Value)
			if err != nil {
				return AuthorizedKeyConstraints{}, eris.Wrap(err, "decode authorized_keys command option")
			}
			if strings.TrimSpace(command) == "" {
				return AuthorizedKeyConstraints{}, eris.New("authorized_keys command option must not be empty")
			}
			if strings.ContainsRune(command, '\x00') {
				return AuthorizedKeyConstraints{}, eris.New("authorized_keys command option contains NUL")
			}
			if len(command) > 24<<10 {
				return AuthorizedKeyConstraints{}, eris.New("authorized_keys command option exceeds maximum size")
			}
			constraints.ForcedCommand = command
		case "no-pty":
			if option.HasValue {
				return AuthorizedKeyConstraints{}, eris.New("authorized_keys no-pty option must not have a value")
			}
			constraints.NoPTY = true
		case "restrict":
			if option.HasValue {
				return AuthorizedKeyConstraints{}, eris.New("authorized_keys restrict option must not have a value")
			}
			constraints.Restricted = true
			constraints.NoPTY = true
		default:
			return AuthorizedKeyConstraints{}, eris.Errorf("unsupported authorized_keys option %q", option.Name)
		}
	}
	return constraints, nil
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
