package user

import (
	"context"
	osuser "os/user"

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

	usr, err := osuser.Lookup(username)
	if err != nil {
		return Account{}, eris.Wrapf(err, "lookup user %q", username)
	}

	uid, err := ParseID(usr.Uid)
	if err != nil {
		return Account{}, eris.Wrapf(err, "parse uid %q for user %q", usr.Uid, username)
	}

	primaryGroup, err := lookupGroup(usr.Gid)
	if err != nil {
		return Account{}, eris.Wrapf(err, "lookup primary group %q for user %q", usr.Gid, username)
	}

	supplementaryGroups, err := lookupSupplementaryGroups(usr, primaryGroup.Id)
	if err != nil {
		return Account{}, eris.Wrapf(err, "lookup supplementary groups for user %q", username)
	}

	return Account{
		Username:            usr.Username,
		Name:                usr.Name,
		Id:                  uid,
		PrimaryGroup:        primaryGroup,
		SupplementaryGroups: supplementaryGroups,
		HomeDir:             usr.HomeDir,
	}, nil
}

func LookupAccount(username string) (Account, error) {
	return (OSResolver{}).Resolve(context.Background(), username)
}

func CloneAccount(account Account) Account {
	account.SupplementaryGroups = append([]Group(nil), account.SupplementaryGroups...)
	return account
}

func lookupGroup(groupID string) (Group, error) {
	gid, err := ParseID(groupID)
	if err != nil {
		return Group{}, eris.Wrapf(err, "parse gid %q", groupID)
	}

	group, err := osuser.LookupGroupId(groupID)
	if err != nil {
		return Group{}, eris.Wrapf(err, "lookup group %q", groupID)
	}

	return Group{
		Id:   gid,
		Name: group.Name,
	}, nil
}

func lookupSupplementaryGroups(usr *osuser.User, primaryGroupID GUID) ([]Group, error) {
	groupIDs, err := usr.GroupIds()
	if err != nil {
		return nil, eris.Wrapf(err, "list groups for user %q", usr.Username)
	}

	supplementaryGroups := make([]Group, 0, len(groupIDs))
	seen := map[GUID]struct{}{
		primaryGroupID: {},
	}

	for _, groupID := range groupIDs {
		gid, err := ParseID(groupID)
		if err != nil {
			return nil, eris.Wrapf(err, "parse supplementary gid %q for user %q", groupID, usr.Username)
		}
		if _, ok := seen[gid]; ok {
			continue
		}

		group, err := osuser.LookupGroupId(groupID)
		if err != nil {
			return nil, eris.Wrapf(err, "lookup supplementary group %q for user %q", groupID, usr.Username)
		}

		seen[gid] = struct{}{}
		supplementaryGroups = append(supplementaryGroups, Group{
			Id:   gid,
			Name: group.Name,
		})
	}

	return supplementaryGroups, nil
}
