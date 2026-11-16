package users

import (
	"strconv"
	"strings"
)

// RuntimeUser is for runtimes that resolve user names inside the container.
// A numeric "uid:gid" is returned as ids; anything else is returned as a
// name with uid and gid 0.
func RuntimeUser(user string) (*ExecUser, string) {
	if uidStr, gidStr, ok := strings.Cut(user, ":"); ok {
		uid, uidErr := strconv.ParseUint(uidStr, 10, 31)
		gid, gidErr := strconv.ParseUint(gidStr, 10, 31)
		if uidErr == nil && gidErr == nil {
			return &ExecUser{Uid: int(uid), Gid: int(gid), Sgids: []int{}}, ""
		}
	}

	return &ExecUser{Uid: DefaultUID, Gid: DefaultGID, Sgids: []int{}}, user
}
