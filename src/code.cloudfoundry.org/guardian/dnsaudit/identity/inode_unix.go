//go:build !windows

package identity

import (
	"io/fs"
	"syscall"
)

// inode returns the inode number of a file, which for a cgroup v2 directory is
// its cgroup ID.
func inode(info fs.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Ino), true
}
