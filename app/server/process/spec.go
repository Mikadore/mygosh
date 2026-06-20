package process

import (
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rotisserie/eris"
)

const (
	defaultTerminationGrace = 2 * time.Second
	maxEnvironmentEntries   = 256
)

var protectedEnvironment = map[string]struct{}{
	"HOME":    {},
	"USER":    {},
	"LOGNAME": {},
	"SHELL":   {},
	"PATH":    {},
}

type PTYSpec struct {
	Terminal string
	Rows     uint32
	Columns  uint32
}

// Spec is plain, already-authorized process input. Runner does not resolve
// accounts, inspect files, or make policy decisions.
type Spec struct {
	Executable           string
	Argv                 []string
	WorkingDirectory     string
	TrustedEnvironment   map[string]string
	RequestedEnvironment map[string]string
	UID                  uint32
	GID                  uint32
	SupplementaryGroups  []uint32
	PTY                  *PTYSpec
	TerminationGrace     time.Duration
}

func (s Spec) clone() Spec {
	s.Argv = append([]string(nil), s.Argv...)
	s.SupplementaryGroups = append([]uint32(nil), s.SupplementaryGroups...)
	s.TrustedEnvironment = cloneEnvironment(s.TrustedEnvironment)
	s.RequestedEnvironment = cloneEnvironment(s.RequestedEnvironment)
	if s.PTY != nil {
		pty := *s.PTY
		s.PTY = &pty
	}
	return s
}

func (s Spec) validate() error {
	if !filepath.IsAbs(s.Executable) {
		return eris.New("process executable must be absolute")
	}
	if len(s.Argv) == 0 || s.Argv[0] == "" {
		return eris.New("process argv[0] is required")
	}
	if !filepath.IsAbs(s.WorkingDirectory) {
		return eris.New("process working directory must be absolute")
	}
	if s.TerminationGrace < 0 {
		return eris.New("process termination grace must be non-negative")
	}
	if len(s.TrustedEnvironment)+len(s.RequestedEnvironment) > maxEnvironmentEntries {
		return eris.New("process environment has too many entries")
	}
	for name, value := range s.TrustedEnvironment {
		if err := validateEnvironment(name, value); err != nil {
			return err
		}
	}
	for name, value := range s.RequestedEnvironment {
		if err := validateEnvironment(name, value); err != nil {
			return err
		}
		if _, protected := protectedEnvironment[name]; protected {
			return eris.Errorf("requested environment cannot replace trusted %s", name)
		}
	}
	seenGroups := make(map[uint32]struct{}, len(s.SupplementaryGroups))
	for _, group := range s.SupplementaryGroups {
		if group == s.GID {
			return eris.New("supplementary groups must not repeat the primary GID")
		}
		if _, exists := seenGroups[group]; exists {
			return eris.Errorf("duplicate supplementary GID %d", group)
		}
		seenGroups[group] = struct{}{}
	}
	if s.PTY != nil {
		if s.PTY.Rows == 0 || s.PTY.Rows > 65535 || s.PTY.Columns == 0 || s.PTY.Columns > 65535 {
			return eris.New("PTY dimensions are invalid")
		}
		if strings.ContainsRune(s.PTY.Terminal, '\x00') {
			return eris.New("PTY terminal contains NUL")
		}
	}
	return nil
}

func (s Spec) environment() []string {
	combined := cloneEnvironment(s.TrustedEnvironment)
	for name, value := range s.RequestedEnvironment {
		combined[name] = value
	}
	names := make([]string, 0, len(combined))
	for name := range combined {
		names = append(names, name)
	}
	slices.Sort(names)
	environment := make([]string, 0, len(names))
	for _, name := range names {
		environment = append(environment, name+"="+combined[name])
	}
	return environment
}

func (s Spec) grace() time.Duration {
	if s.TerminationGrace == 0 {
		return defaultTerminationGrace
	}
	return s.TerminationGrace
}

func validateEnvironment(name string, value string) error {
	if name == "" || strings.ContainsAny(name, "=\x00") {
		return eris.Errorf("invalid environment variable name %q", name)
	}
	if strings.ContainsRune(value, '\x00') {
		return eris.Errorf("environment variable %q contains NUL", name)
	}
	return nil
}

func cloneEnvironment(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for name, value := range source {
		copy[name] = value
	}
	return copy
}
