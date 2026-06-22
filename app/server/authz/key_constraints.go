package authz

import (
	"github.com/Mikadore/mygosh/lib/trust"
	"github.com/rotisserie/eris"
)

type MatchedKeyConstraints struct {
	forcedCommand string
	noPTY         bool
	restricted    bool
}

func newMatchedKeyConstraints(constraints trust.AuthorizedKeyConstraints) MatchedKeyConstraints {
	return MatchedKeyConstraints{
		forcedCommand: constraints.ForcedCommand,
		noPTY:         constraints.NoPTY,
		restricted:    constraints.Restricted,
	}
}

func (c MatchedKeyConstraints) ForcedCommand() string {
	return c.forcedCommand
}

func (c MatchedKeyConstraints) NoPTY() bool {
	return c.noPTY
}

func (c MatchedKeyConstraints) Restricted() bool {
	return c.restricted
}

func (c MatchedKeyConstraints) validate() error {
	if c.restricted && !c.noPTY {
		return eris.New("restricted authorized key must disable PTY")
	}
	if len(c.forcedCommand) > 24<<10 {
		return eris.New("authorized key forced command exceeds maximum size")
	}
	return nil
}

func applyMatchedKeyConstraints(decision PermissionDecision, constraints MatchedKeyConstraints) (PermissionDecision, error) {
	if err := constraints.validate(); err != nil {
		return PermissionDecision{}, err
	}
	if constraints.noPTY {
		decision.AllowPTY = false
	}
	if constraints.forcedCommand != "" {
		if decision.ForcedCommand != "" && decision.ForcedCommand != constraints.forcedCommand {
			return PermissionDecision{}, eris.New("configured and authorized-key forced commands conflict")
		}
		decision.ForcedCommand = constraints.forcedCommand
	}
	return decision, nil
}
