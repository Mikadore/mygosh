package account

import (
	osuser "os/user"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGroupGIDReturnsString(t *testing.T) {
	group := Group{
		Id:   27,
		Name: "sudo",
	}

	require.Equal(t, "27", group.GID())
}

func TestAccountUIDAndGIDReturnString(t *testing.T) {
	account := Account{
		Id: 1000,
		PrimaryGroup: Group{
			Id:   100,
			Name: "users",
		},
	}

	require.Equal(t, "1000", account.UID())
	require.Equal(t, "100", account.GID())
}

func TestLookupAccountReturnsCurrentUser(t *testing.T) {
	currentUser, err := osuser.Current()
	require.NoError(t, err)

	account, err := LookupAccount(currentUser.Username)
	require.NoError(t, err)

	expectedUID, err := ParseID(currentUser.Uid)
	require.NoError(t, err)

	expectedPrimaryGID, err := ParseID(currentUser.Gid)
	require.NoError(t, err)

	expectedPrimaryGroup, err := osuser.LookupGroupId(currentUser.Gid)
	require.NoError(t, err)

	expectedSupplementaryGroups, err := expectedSupplementaryGroups(currentUser)
	require.NoError(t, err)

	pwd, err := getpwnamR(currentUser.Username)
	require.NoError(t, err)

	require.Equal(t, Account{
		Username: currentUser.Username,
		Name:     currentUser.Name,
		Id:       expectedUID,
		PrimaryGroup: Group{
			Id:   expectedPrimaryGID,
			Name: expectedPrimaryGroup.Name,
		},
		SupplementaryGroups: expectedSupplementaryGroups,
		HomeDir:             currentUser.HomeDir,
		LoginShell:          pwd.pw_shell,
	}, account)
	require.Equal(t, currentUser.Uid, account.UID())
	require.Equal(t, currentUser.Gid, account.GID())
}

func expectedSupplementaryGroups(usr *osuser.User) ([]Group, error) {
	groupIDs, err := usr.GroupIds()
	if err != nil {
		return nil, err
	}

	primaryGroupID, err := ParseID(usr.Gid)
	if err != nil {
		return nil, err
	}

	supplementaryGroups := make([]Group, 0, len(groupIDs))
	seen := map[GUID]struct{}{
		primaryGroupID: {},
	}

	for _, groupID := range groupIDs {
		gid, err := ParseID(groupID)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[gid]; ok {
			continue
		}

		group, err := osuser.LookupGroupId(groupID)
		if err != nil {
			return nil, err
		}

		seen[gid] = struct{}{}
		supplementaryGroups = append(supplementaryGroups, Group{
			Id:   gid,
			Name: group.Name,
		})
	}

	return supplementaryGroups, nil
}
