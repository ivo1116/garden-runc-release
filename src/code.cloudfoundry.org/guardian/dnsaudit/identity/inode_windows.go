package identity

import "io/fs"

// There are no cgroups on Windows; dns-audit only runs on Linux.
func inode(fs.FileInfo) (uint64, bool) {
	return 0, false
}
