package audit_test

import (
	"time"

	"code.cloudfoundry.org/guardian/dnsaudit/audit"
	"code.cloudfoundry.org/guardian/dnsaudit/identity"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Excluder", func() {
	var excluder *audit.Excluder

	BeforeEach(func() {
		excluder = audit.NewExcluder([]string{"cf.internal", ".Apps.Internal.", " bosh ", ""})
	})

	DescribeTable("matching",
		func(name string, excluded bool) {
			Expect(excluder.Excluded(name)).To(Equal(excluded))
		},
		Entry("exact", "cf.internal", true),
		Entry("subdomain", "foo.cf.internal", true),
		Entry("not on a label boundary", "xcf.internal", false),
		Entry("unrelated", "example.com", false),
		Entry("normalised suffix", "app.apps.internal", true),
		Entry("trimmed suffix", "group.bosh", true),
		Entry("escaped dot", `a\.cf.internal`, false),
		Entry("escaped backslash before a dot", `a\\.cf.internal`, true),
	)
})

var _ = Describe("Deduper", func() {
	var (
		deduper *audit.Deduper
		start   time.Time
		c1, c2  identity.Container
	)

	// seen checks a query and marks it as logged when it may be logged, like
	// the processor does when the rate limit allows it.
	seen := func(c identity.Container, name, qtype string, now time.Time) (bool, uint64, bool) {
		log, repeats, full := deduper.Check(c, name, qtype, now)
		if log {
			deduper.Logged(c, name, qtype, now)
		}
		return log, repeats, full
	}

	BeforeEach(func() {
		deduper = audit.NewDeduper(time.Minute, 1<<20)
		start = time.Unix(1000, 0)
		c1 = identity.Container{Handle: "handle-1"}
		c2 = identity.Container{Handle: "handle-2"}
	})

	It("logs the first query, suppresses repeats in the window and reports them next time", func() {
		log, repeats, full := seen(c1, "example.com", "A", start)
		Expect([]any{log, repeats, full}).To(Equal([]any{true, uint64(0), false}))
		for i := 1; i <= 3; i++ {
			log, _, _ = seen(c1, "example.com", "A", start.Add(time.Duration(i)*time.Second))
			Expect(log).To(BeFalse())
		}
		log, repeats, _ = seen(c1, "example.com", "A", start.Add(time.Minute))
		Expect(log).To(BeTrue())
		Expect(repeats).To(Equal(uint64(3)))
	})

	It("tracks container, name and type separately", func() {
		Expect(first(seen(c1, "example.com", "A", start))).To(BeTrue())
		Expect(first(seen(c2, "example.com", "A", start))).To(BeTrue())
		Expect(first(seen(c1, "example.com", "AAAA", start))).To(BeTrue())
		Expect(first(seen(c1, "example.com", "A", start))).To(BeFalse())
	})

	It("starts a window only for queries that were logged", func() {
		Expect(first(deduper.Check(c1, "dropped.example", "A", start))).To(BeTrue())
		Expect(deduper.Len()).To(BeZero())
		Expect(first(deduper.Check(c1, "dropped.example", "A", start.Add(time.Second)))).To(BeTrue(), "not a repeat of a query that wasn't logged")
	})

	It("keeps counting repeats until the query is logged again", func() {
		seen(c1, "example.com", "A", start)
		seen(c1, "example.com", "A", start.Add(time.Second))

		log, repeats, _ := deduper.Check(c1, "example.com", "A", start.Add(time.Minute))
		Expect(log).To(BeTrue())
		Expect(repeats).To(Equal(uint64(1)))

		log, repeats, _ = seen(c1, "example.com", "A", start.Add(time.Minute+time.Second))
		Expect(log).To(BeTrue())
		Expect(repeats).To(Equal(uint64(1)), "the earlier check wasn't followed by Logged")
	})

	It("bounds its memory and logs without tracking when full", func() {
		deduper = audit.NewDeduper(time.Minute, 450)
		Expect(third(seen(c1, "a.example", "A", start))).To(BeFalse())
		Expect(third(seen(c1, "b.example", "A", start))).To(BeFalse())
		Expect(third(seen(c1, "c.example", "A", start))).To(BeFalse())

		log, _, full := seen(c1, "d.example", "A", start)
		Expect(log).To(BeTrue())
		Expect(full).To(BeTrue())
		Expect(deduper.Len()).To(Equal(3))
		Expect(deduper.Bytes()).To(BeNumerically("<=", 450))
	})

	It("prunes idle entries, reports their repeats and frees their memory", func() {
		seen(c1, "example.com", "A", start)
		seen(c1, "example.com", "A", start.Add(time.Second))
		seen(c2, "quiet.example", "A", start)

		Expect(deduper.Prune(start.Add(30 * time.Second))).To(BeEmpty())
		flushed := deduper.Prune(start.Add(time.Second + time.Minute))
		Expect(flushed).To(Equal([]audit.Repeats{{Container: c1, Name: "example.com", Type: "A", Suppressed: 1}}))
		Expect(deduper.Len()).To(BeZero())
		Expect(deduper.Bytes()).To(BeZero())
	})
})

var _ = Describe("RateLimiter", func() {
	var (
		limiter *audit.RateLimiter
		start   time.Time
		c1, c2  identity.Container
	)

	allow := func(c identity.Container, name string, now time.Time) bool {
		allowed, _ := limiter.Allow(c, name, now)
		return allowed
	}

	BeforeEach(func() {
		limiter = audit.NewRateLimiter(2, 4, 0, 0, 3, 2)
		start = time.Unix(1000, 0)
		c1 = identity.Container{Handle: "handle-1"}
		c2 = identity.Container{Handle: "handle-2"}
	})

	It("allows a burst, then the steady rate", func() {
		for i := 0; i < 4; i++ {
			Expect(allow(c1, "x.example", start)).To(BeTrue())
		}
		Expect(allow(c1, "x.example", start)).To(BeFalse())
		Expect(allow(c1, "x.example", start.Add(250*time.Millisecond))).To(BeFalse())
		Expect(allow(c1, "x.example", start.Add(500*time.Millisecond))).To(BeTrue())
	})

	It("summarises what it dropped by suffix, most frequent first, once", func() {
		for i := 0; i < 4; i++ {
			allow(c1, "warmup.example", start)
		}
		for _, name := range []string{"a.t1.tunnel.example", "b.t2.tunnel.example", "c.tunnel.example", "x.other.org", "y.third.net", "z.fourth.io"} {
			allow(c1, name, start)
		}

		Expect(limiter.Drain()).To(Equal([]audit.Dropped{{
			Container: c1,
			Dropped:   6,
			TopSuffixes: []audit.SuffixCount{
				{Suffix: "tunnel.example", Count: 3},
				{Suffix: "(other)", Count: 1},
			},
		}}))
		Expect(limiter.Drain()).To(BeEmpty())
	})

	It("forgets buckets that have refilled", func() {
		allow(c1, "x.example", start)
		limiter.Prune(start.Add(time.Second))
		Expect(limiter.Len()).To(BeZero())
	})

	Context("with a cell limit", func() {
		BeforeEach(func() {
			limiter = audit.NewRateLimiter(2, 4, 1, 5, 3, 2)
		})

		It("limits all containers together and says so in the summary", func() {
			for i := 0; i < 4; i++ {
				Expect(allow(c1, "a.example", start)).To(BeTrue())
			}
			Expect(allow(c2, "b.example", start)).To(BeTrue())

			allowed, byCell := limiter.Allow(c2, "b.example", start)
			Expect(allowed).To(BeFalse())
			Expect(byCell).To(BeTrue())

			allowed, byCell = limiter.Allow(c1, "a.example", start)
			Expect(allowed).To(BeFalse())
			Expect(byCell).To(BeFalse(), "c1 is over its own limit")

			Expect(limiter.Drain()).To(Equal([]audit.Dropped{
				{Container: c1, Dropped: 1, TopSuffixes: []audit.SuffixCount{{Suffix: "a.example", Count: 1}}},
				{Container: c2, Dropped: 1, DroppedByCellLimit: 1, TopSuffixes: []audit.SuffixCount{{Suffix: "b.example", Count: 1}}},
			}))
		})

		It("doesn't use up a container's allowance for queries the cell limit dropped", func() {
			limiter = audit.NewRateLimiter(1, 2, 10, 1, 3, 2)
			Expect(allow(c1, "a.example", start)).To(BeTrue())
			Expect(allow(c2, "b.example", start)).To(BeFalse())
			Expect(allow(c2, "b.example", start)).To(BeFalse())

			Expect(allow(c2, "b.example", start.Add(100*time.Millisecond))).To(BeTrue(),
				"the cell limit refilled, and c2 still has its full burst")
		})
	})
})

func first(log bool, _ uint64, _ bool) bool  { return log }
func third(_ bool, _ uint64, full bool) bool { return full }
