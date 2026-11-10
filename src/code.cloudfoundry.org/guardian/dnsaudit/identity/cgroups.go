package identity

import (
	"io/fs"
	"path/filepath"
	"time"
)

// CgroupIndex maps cgroup IDs (the inode numbers of cgroup v2 directories) to
// paths below a root directory. It rescans the tree when it sees an unknown
// ID, at most once per minRescan, and remembers IDs that are still unknown
// after a scan for unknownTTL.
type CgroupIndex struct {
	root       string
	now        func() time.Time
	minRescan  time.Duration
	unknownTTL time.Duration

	paths    map[uint64]string
	unknown  map[uint64]time.Time
	lastScan time.Time
	scans    uint64
}

func NewCgroupIndex(root string, now func() time.Time) *CgroupIndex {
	return &CgroupIndex{
		root:       root,
		now:        now,
		minRescan:  100 * time.Millisecond,
		unknownTTL: 5 * time.Second,
		paths:      map[uint64]string{},
		unknown:    map[uint64]time.Time{},
	}
}

// Path returns the path of the cgroup relative to the root, using "/" as the
// separator. The root itself has the path ".".
func (c *CgroupIndex) Path(id uint64) (string, bool) {
	if path, ok := c.paths[id]; ok {
		return path, true
	}

	now := c.now()
	if seen, ok := c.unknown[id]; ok && now.Sub(seen) < c.unknownTTL {
		return "", false
	}
	if now.Sub(c.lastScan) >= c.minRescan {
		c.Scan()
		if path, ok := c.paths[id]; ok {
			return path, true
		}
	}
	c.unknown[id] = now
	return "", false
}

func (c *CgroupIndex) Scan() {
	paths := map[uint64]string{}
	_ = filepath.WalkDir(c.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		id, ok := inode(info)
		if !ok {
			return nil
		}
		rel, err := filepath.Rel(c.root, path)
		if err != nil {
			return nil
		}
		paths[id] = filepath.ToSlash(rel)
		return nil
	})

	now := c.now()
	c.paths = paths
	c.lastScan = now
	c.scans++
	for id, seen := range c.unknown {
		if now.Sub(seen) >= c.unknownTTL {
			delete(c.unknown, id)
		}
	}
}

func (c *CgroupIndex) Scans() uint64 {
	return c.scans
}
