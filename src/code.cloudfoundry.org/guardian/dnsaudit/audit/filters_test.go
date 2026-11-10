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

	BeforeEach(func() {
		deduper = audit.NewDeduper(time.Minute, 1<<20)
		start = time.Unix(1000, 0)
		c1 = identity.Container{Handle: "handle-1"}
		c2 = identity.Container{Handle: "handle-2"}
	})

	It("logs the first query, suppresses repeats in the window and reports them next time", func() {
		log, repeats, full := deduper.Check(c1, "example.com", "A", start)
		Expect([]any{log, repeats, full}).To(Equal([]any{true, uint64(0), false}))
		for i := 1; i <= 3; i++ {
			log, _, _ = deduper.Check(c1, "example.com", "A", start.Add(time.Duration(i)*time.Second))
			Expect(log).To(BeFalse())
		}
		log, repeats, _ = deduper.Check(c1, "example.com", "A", start.Add(time.Minute))
		Expect(log).To(BeTrue())
		Expect(repeats).To(Equal(uint64(3)))
	})

	It("tracks container, name and type separately", func() {
		Expect(first(deduper.Check(c1, "example.com", "A", start))).To(BeTrue())
		Expect(first(deduper.Check(c2, "example.com", "A", start))).To(BeTrue())
		Expect(first(deduper.Check(c1, "example.com", "AAAA", start))).To(BeTrue())
		Expect(first(deduper.Check(c1, "example.com", "A", start))).To(BeFalse())
	})

	It("bounds its memory and logs without tracking when full", func() {
		deduper = audit.NewDeduper(time.Minute, 450)
		Expect(third(deduper.Check(c1, "a.example", "A", start))).To(BeFalse())
		Expect(third(deduper.Check(c1, "b.example", "A", start))).To(BeFalse())
		Expect(third(deduper.Check(c1, "c.example", "A", start))).To(BeFalse())

		log, _, full := deduper.Check(c1, "d.example", "A", start)
		Expect(log).To(BeTrue())
		Expect(full).To(BeTrue())
		Expect(deduper.Len()).To(Equal(3))
		Expect(deduper.Bytes()).To(BeNumerically("<=", 450))
	})

	It("prunes idle entries, reports their repeats and frees their memory", func() {
		deduper.Check(c1, "example.com", "A", start)
		deduper.Check(c1, "example.com", "A", start.Add(time.Second))
		deduper.Check(c2, "quiet.example", "A", start)

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
		c1      identity.Container
	)

	BeforeEach(func() {
		limiter = audit.NewRateLimiter(2, 4, 3, 2)
		start = time.Unix(1000, 0)
		c1 = identity.Container{Handle: "handle-1"}
	})

	It("allows a burst, then the steady rate", func() {
		for i := 0; i < 4; i++ {
			Expect(limiter.Allow(c1, "x.example", start)).To(BeTrue())
		}
		Expect(limiter.Allow(c1, "x.example", start)).To(BeFalse())
		Expect(limiter.Allow(c1, "x.example", start.Add(250*time.Millisecond))).To(BeFalse())
		Expect(limiter.Allow(c1, "x.example", start.Add(500*time.Millisecond))).To(BeTrue())
	})

	It("summarises what it dropped by suffix, most frequent first, once", func() {
		for i := 0; i < 4; i++ {
			limiter.Allow(c1, "warmup.example", start)
		}
		for _, name := range []string{"a.t1.tunnel.example", "b.t2.tunnel.example", "c.tunnel.example", "x.other.org", "y.third.net", "z.fourth.io"} {
			limiter.Allow(c1, name, start)
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
		limiter.Allow(c1, "x.example", start)
		limiter.Prune(start.Add(time.Second))
		Expect(limiter.Len()).To(BeZero())
	})
})

func first(log bool, _ uint64, _ bool) bool  { return log }
func third(_ bool, _ uint64, full bool) bool { return full }
