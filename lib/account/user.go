//go:build linux || darwin || freebsd || openbsd || netbsd

package account

import (
	"context"
	"strings"

	"github.com/rotisserie/eris"
)

type UID = uint32
type GUID = uint32

type Group struct {
	Id   GUID
	Name string
}

func (g Group) GID() string {
	return FormatID(g.Id)
}

type Account struct {
	Username            string
	Name                string
	Id                  UID
	PrimaryGroup        Group
	SupplementaryGroups []Group
	HomeDir             string
	LoginShell          string
}

func (a Account) UID() string {
	return FormatID(a.Id)
}

func (a Account) GID() string {
	return a.PrimaryGroup.GID()
}

type Resolver interface {
	Resolve(ctx context.Context, username string) (Account, error)
}

type ResolverFunc func(ctx context.Context, username string) (Account, error)

func (f ResolverFunc) Resolve(ctx context.Context, username string) (Account, error) {
	if f == nil {
		return Account{}, eris.New("account resolver is required")
	}
	return f(ctx, username)
}

type OSResolver struct{}

func (OSResolver) Resolve(ctx context.Context, username string) (Account, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Account{}, err
	}

	pwd, err := getpwnamR(username)
	if err != nil {
		return Account{}, eris.Wrapf(err, "lookup user %q", username)
	}

	primaryGroup, err := lookupGroup(pwd.pw_gid)
	if err != nil {
		return Account{}, eris.Wrapf(err, "lookup primary group %q for user %q", FormatID(pwd.pw_gid), username)
	}

	supplementaryGroups, err := lookupSupplementaryGroups(pwd, primaryGroup.Id)
	if err != nil {
		return Account{}, eris.Wrapf(err, "lookup supplementary groups for user %q", username)
	}

	name, _, _ := strings.Cut(pwd.pw_gecos, ",")
	return Account{
		Username:            pwd.pw_name,
		Name:                name,
		Id:                  pwd.pw_uid,
		PrimaryGroup:        primaryGroup,
		SupplementaryGroups: supplementaryGroups,
		HomeDir:             pwd.pw_dir,
		LoginShell:          pwd.pw_shell,
	}, nil
}

func LookupAccount(username string) (Account, error) {
	return (OSResolver{}).Resolve(context.Background(), username)
}

func CloneAccount(account Account) Account {
	account.SupplementaryGroups = append([]Group(nil), account.SupplementaryGroups...)
	return account
}

func lookupGroup(groupID GUID) (Group, error) {
	groupName, err := getgrgidR(groupID)
	if err != nil {
		return Group{}, eris.Wrapf(err, "lookup group %q", FormatID(groupID))
	}

	return Group{
		Id:   groupID,
		Name: groupName,
	}, nil
}

func lookupSupplementaryGroups(pwd *passwd_t, primaryGroupID GUID) ([]Group, error) {
	groupIDs, err := getgrouplist(pwd.pw_name, primaryGroupID)
	if err != nil {
		return nil, eris.Wrapf(err, "list groups for user %q", pwd.pw_name)
	}

	supplementaryGroups := make([]Group, 0, len(groupIDs))
	seen := map[GUID]struct{}{
		primaryGroupID: {},
	}

	for _, groupID := range groupIDs {
		if _, ok := seen[groupID]; ok {
			continue
		}

		group, err := lookupGroup(groupID)
		if err != nil {
			return nil, eris.Wrapf(err, "lookup supplementary group %q for user %q", FormatID(groupID), pwd.pw_name)
		}

		seen[groupID] = struct{}{}
		supplementaryGroups = append(supplementaryGroups, group)
	}

	return supplementaryGroups, nil
}
