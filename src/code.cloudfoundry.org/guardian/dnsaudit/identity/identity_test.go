package identity_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/dnsaudit/identity"
	"code.cloudfoundry.org/guardian/dnsaudit/identity/fakes"
	"code.cloudfoundry.org/lager/v3/lagertest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func inode(path string) uint64 {
	info, err := os.Stat(path)
	Expect(err).NotTo(HaveOccurred())
	return uint64(info.Sys().(*syscall.Stat_t).Ino)
}

func mkdir(parts ...string) string {
	path := filepath.Join(parts...)
	Expect(os.MkdirAll(path, 0755)).To(Succeed())
	return path
}

var _ = Describe("CgroupIndex", func() {
	var (
		root  string
		clock *fakeClock
		index *identity.CgroupIndex
	)

	BeforeEach(func() {
		root = GinkgoT().TempDir()
		clock = &fakeClock{now: time.Unix(1000, 0)}
		index = identity.NewCgroupIndex(root, clock.Now)
	})

	It("maps cgroup IDs to paths below the root", func() {
		init := mkdir(root, "handle-1", "init")
		index.Scan()

		path, ok := index.Path(inode(init))
		Expect(ok).To(BeTrue())
		Expect(path).To(Equal("handle-1/init"))

		path, ok = index.Path(inode(root))
		Expect(ok).To(BeTrue())
		Expect(path).To(Equal("."))
	})

	It("rescans when it sees an unknown ID", func() {
		index.Scan()
		clock.Advance(time.Second)
		init := mkdir(root, "handle-2", "init")

		path, ok := index.Path(inode(init))
		Expect(ok).To(BeTrue())
		Expect(path).To(Equal("handle-2/init"))
	})

	It("rescans at most once per interval and remembers unknown IDs for a while", func() {
		index.Scan()
		Expect(index.Scans()).To(Equal(uint64(1)))

		_, ok := index.Path(424242)
		Expect(ok).To(BeFalse())
		Expect(index.Scans()).To(Equal(uint64(1)))

		clock.Advance(time.Second)
		_, ok = index.Path(424242)
		Expect(ok).To(BeFalse())
		Expect(index.Scans()).To(Equal(uint64(1)), "unknown IDs aren't rescanned for a while")

		_, ok = index.Path(434343)
		Expect(ok).To(BeFalse())
		Expect(index.Scans()).To(Equal(uint64(2)))

		clock.Advance(10 * time.Second)
		_, ok = index.Path(424242)
		Expect(ok).To(BeFalse())
		Expect(index.Scans()).To(Equal(uint64(3)))
	})

	It("forgets removed cgroups on the next scan", func() {
		dir := mkdir(root, "handle-3")
		id := inode(dir)
		index.Scan()
		Expect(os.Remove(dir)).To(Succeed())
		index.Scan()

		_, ok := index.Path(id)
		Expect(ok).To(BeFalse())
	})
})

var _ = Describe("Resolver", func() {
	var (
		root     string
		clock    *fakeClock
		source   *fakes.PropertySource
		resolver *identity.Resolver
		keys     []string
	)

	logConfig := `{"guid":"app-guid","index":0,"source_name":"CELL","tags":{"app_name":"my-app","space_name":"my-space","organization_name":"my-org","instance_id":"0"}}`

	BeforeEach(func() {
		root = GinkgoT().TempDir()
		clock = &fakeClock{now: time.Unix(1000, 0)}
		source = &fakes.PropertySource{}
		source.HandlesReturns([]string{"handle-1", "handle-10"}, nil)
		source.PropertiesStub = func(handle string) (map[string]string, error) {
			return map[string]string{
				"network.app_id": "app-guid-of-" + handle,
				"log_config":     logConfig,
				"garden.state":   "created",
			}, nil
		}
		keys = []string{"network.app_id", "app_name", "space_name", "missing"}
	})

	JustBeforeEach(func() {
		index := identity.NewCgroupIndex(root, clock.Now)
		resolver = identity.NewResolver(index, source, keys, time.Minute, clock.Now, lagertest.NewTestLogger("resolver"))
	})

	It("resolves a container cgroup to its handle and selected properties", func() {
		init := mkdir(root, "handle-1", "init")

		c, ok := resolver.Resolve(inode(init))
		Expect(ok).To(BeTrue())
		Expect(c).To(Equal(identity.Container{
			Handle: "handle-1",
			Cgroup: "handle-1/init",
			Properties: map[string]string{
				"network.app_id": "app-guid-of-handle-1",
				"app_name":       "my-app",
				"space_name":     "my-space",
			},
		}))
	})

	It("resolves sibling cgroups of processes to the longest matching handle", func() {
		healthcheck := mkdir(root, "handle-10-liveness-healthcheck-0")

		c, ok := resolver.Resolve(inode(healthcheck))
		Expect(ok).To(BeTrue())
		Expect(c.Handle).To(Equal("handle-10"))
		Expect(c.Cgroup).To(Equal("handle-10-liveness-healthcheck-0"))
	})

	It("skips the throttling parent cgroups", func() {
		init := mkdir(root, "bad", "handle-1", "init")

		c, ok := resolver.Resolve(inode(init))
		Expect(ok).To(BeTrue())
		Expect(c.Handle).To(Equal("handle-1"))
		Expect(c.Cgroup).To(Equal("handle-1/init"))
	})

	It("does not resolve the root or unknown cgroups", func() {
		_, ok := resolver.Resolve(inode(root))
		Expect(ok).To(BeFalse())
		_, ok = resolver.Resolve(99999999)
		Expect(ok).To(BeFalse())
		Expect(resolver.UnknownCgroups.Load()).To(Equal(uint64(2)))
	})

	It("caches properties for the TTL", func() {
		init := mkdir(root, "handle-1", "init")
		resolver.Resolve(inode(init))
		resolver.Resolve(inode(init))
		Expect(source.PropertiesCallCount()).To(Equal(1))

		clock.Advance(2 * time.Minute)
		resolver.Resolve(inode(init))
		Expect(source.PropertiesCallCount()).To(Equal(2))
	})

	Context("when no properties are configured", func() {
		BeforeEach(func() {
			keys = nil
		})

		It("doesn't ask Garden for properties", func() {
			init := mkdir(root, "handle-1", "init")
			c, ok := resolver.Resolve(inode(init))
			Expect(ok).To(BeTrue())
			Expect(c.Properties).To(BeNil())
			Expect(source.PropertiesCallCount()).To(BeZero())
		})
	})

	Context("when Garden fails", func() {
		It("returns the handle without properties, counts the error and retries later", func() {
			init := mkdir(root, "handle-1", "init")
			source.PropertiesStub = nil
			source.PropertiesReturns(nil, errors.New("garden down"))

			c, ok := resolver.Resolve(inode(init))
			Expect(ok).To(BeTrue())
			Expect(c.Handle).To(Equal("handle-1"))
			Expect(c.Properties).To(BeNil())
			Expect(resolver.GardenErrors.Load()).To(Equal(uint64(1)))

			resolver.Resolve(inode(init))
			Expect(source.PropertiesCallCount()).To(Equal(1))

			clock.Advance(10 * time.Second)
			source.PropertiesReturns(map[string]string{"network.app_id": "late"}, nil)
			c, _ = resolver.Resolve(inode(init))
			Expect(c.Properties).To(Equal(map[string]string{"network.app_id": "late"}))
		})

		It("keeps the cached properties when a refresh fails", func() {
			init := mkdir(root, "handle-1", "init")
			resolver.Resolve(inode(init))

			clock.Advance(2 * time.Minute)
			source.PropertiesStub = nil
			source.PropertiesReturns(nil, errors.New("garden down"))
			c, _ := resolver.Resolve(inode(init))
			Expect(c.Properties).To(HaveKeyWithValue("app_name", "my-app"))
		})

		It("uses the cgroup name as the handle when Garden can't list containers", func() {
			source.HandlesReturns(nil, errors.New("garden down"))
			init := mkdir(root, "handle-1", "init")
			c, ok := resolver.Resolve(inode(init))
			Expect(ok).To(BeTrue())
			Expect(c.Handle).To(Equal("handle-1"))
			Expect(resolver.GardenErrors.Load()).To(BeNumerically(">=", 1))
		})
	})

	It("drops cached properties of containers that no longer exist", func() {
		init := mkdir(root, "handle-1", "init")
		resolver.Resolve(inode(init))
		Expect(source.PropertiesCallCount()).To(Equal(1))

		source.HandlesReturns([]string{"handle-10"}, nil)
		clock.Advance(2 * time.Second)
		other := mkdir(root, "handle-10-envoy")
		resolver.Resolve(inode(other))

		source.HandlesReturns([]string{"handle-1", "handle-10"}, nil)
		clock.Advance(2 * time.Second)
		resolver.Resolve(inode(init))
		Expect(source.PropertiesCallCount()).To(Equal(3))
	})
})

var _ = Describe("Select", func() {
	It("prefers properties over log_config tags", func() {
		selected := identity.Select(map[string]string{
			"app_name":   "from-property",
			"log_config": `{"tags":{"app_name":"from-tag","space_name":"space"}}`,
		}, []string{"app_name", "space_name"})
		Expect(selected).To(Equal(map[string]string{"app_name": "from-property", "space_name": "space"}))
	})

	It("ignores an invalid log_config", func() {
		selected := identity.Select(map[string]string{"log_config": "{not json"}, []string{"app_name"})
		Expect(selected).To(BeEmpty())
	})
})
