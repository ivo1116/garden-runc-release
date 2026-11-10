package audit_test

import (
	"encoding/json"
	"time"

	"code.cloudfoundry.org/guardian/dnsaudit/audit"
	"code.cloudfoundry.org/guardian/dnsaudit/audit/fakes"
	"code.cloudfoundry.org/guardian/dnsaudit/identity"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

var _ = Describe("Processor", func() {
	var (
		resolver  *fakes.Resolver
		logger    *lagertest.TestLogger
		clock     *fakeClock
		opts      audit.Options
		processor *audit.Processor
		captured  time.Time
	)

	container := identity.Container{
		Handle:     "handle-1",
		Cgroup:     "handle-1/init",
		Properties: map[string]string{"network.app_id": "app-1", "app_name": "my-app"},
	}

	logs := func(message string) []lager.LogFormat {
		var out []lager.LogFormat
		for _, l := range logger.Logs() {
			if l.Message == "dns."+message {
				out = append(out, l)
			}
		}
		return out
	}

	dataJSON := func(l lager.LogFormat) string {
		b, err := json.Marshal(l.Data)
		Expect(err).NotTo(HaveOccurred())
		return string(b)
	}

	egress := func(pkt []byte) audit.Event {
		return audit.Event{CgroupID: 42, Time: captured, Direction: audit.Egress, Data: pkt}
	}
	ingress := func(pkt []byte) audit.Event {
		return audit.Event{CgroupID: 42, Time: captured, Direction: audit.Ingress, Data: pkt}
	}

	BeforeEach(func() {
		resolver = &fakes.Resolver{}
		resolver.ResolveStub = func(id uint64) (identity.Container, bool) {
			if id == 42 {
				return container, true
			}
			return identity.Container{}, false
		}
		logger = lagertest.NewTestLogger("dns")
		clock = &fakeClock{now: time.Unix(1000, 0)}
		captured = time.Date(2026, 11, 5, 10, 15, 2, 123456789, time.UTC)
		opts = audit.Options{
			DedupWindow:     time.Minute,
			RatePerSecond:   1,
			Burst:           3,
			ExcludeDomains:  []string{"cf.internal"},
			ResponseTimeout: 2 * time.Second,
			MaxDedupBytes:   1 << 20,
			MaxPending:      100,
			MaxSuffixes:     10,
			TopSuffixes:     5,
			Host:            audit.Host{IP: "10.0.73.1", ID: "cell-id"},
		}
	})

	JustBeforeEach(func() {
		processor = audit.NewProcessor(opts, resolver, logger, clock.Now)
	})

	It("logs a query with the container, host and query details", func() {
		processor.Handle(egress(queryPacket(51812, 41234, "Example.COM")))

		Expect(logs("dns-query")).To(HaveLen(1))
		Expect(dataJSON(logs("dns-query")[0])).To(MatchJSON(`{
			"container": {
				"handle": "handle-1",
				"cgroup": "handle-1/init",
				"properties": {"network.app_id": "app-1", "app_name": "my-app"}
			},
			"host": {"ip": "10.0.73.1", "id": "cell-id"},
			"query": {
				"name": "example.com", "type": "A", "id": 51812, "protocol": "udp", "family": "ipv4",
				"src_ip": "10.255.0.1", "src_port": 41234, "dst_ip": "169.254.0.53", "dst_port": 53,
				"time": "2026-11-05T10:15:02.123456789Z"
			},
			"repeats_suppressed": 0
		}`))
		Expect(processor.Counters.QueriesLogged.Load()).To(Equal(uint64(1)))
	})

	It("ignores packets from unknown cgroups", func() {
		processor.Handle(audit.Event{CgroupID: 7, Direction: audit.Egress, Data: queryPacket(1, 1, "example.com")})
		Expect(logs("dns-query")).To(BeEmpty())
	})

	It("counts packets it can't use", func() {
		processor.Handle(egress([]byte{0x45, 0}))
		processor.Handle(egress(responsePacket(1, 1, "example.com", 0)))
		processor.Handle(egress(udpPacket("10.0.0.1", "10.0.0.2", 1, 53, dnsMessage(1, 0x2800, "example.com", 1))))
		Expect(processor.Counters.Malformed.Load()).To(Equal(uint64(1)))
		Expect(processor.Counters.NotQuery.Load()).To(Equal(uint64(2)))
		Expect(processor.Counters.Events.Load()).To(Equal(uint64(3)))
		Expect(logs("dns-query")).To(BeEmpty())
		Expect(resolver.ResolveCallCount()).To(BeZero())
	})

	It("doesn't log excluded names", func() {
		processor.Handle(egress(queryPacket(1, 1, "foo.cf.internal")))
		Expect(logs("dns-query")).To(BeEmpty())
		Expect(processor.Counters.Excluded.Load()).To(Equal(uint64(1)))
	})

	It("suppresses repeats and reports them with the next query", func() {
		for i := 0; i < 3; i++ {
			processor.Handle(egress(queryPacket(uint16(i), 1, "example.com")))
		}
		Expect(logs("dns-query")).To(HaveLen(1))
		Expect(processor.Counters.QueriesSuppressed.Load()).To(Equal(uint64(2)))

		clock.Advance(30 * time.Second)
		processor.Handle(egress(queryPacket(9, 1, "example.com")))
		clock.Advance(30 * time.Second)
		processor.Handle(egress(queryPacket(10, 1, "example.com")))

		Expect(logs("dns-query")).To(HaveLen(2))
		Expect(logs("dns-query")[1].Data["repeats_suppressed"]).To(BeNumerically("==", 3))
	})

	It("reports repeats of a query that stops in a summary", func() {
		processor.Handle(egress(queryPacket(1, 1, "beacon.example")))
		processor.Handle(egress(queryPacket(2, 1, "beacon.example")))

		clock.Advance(time.Minute)
		processor.Tick()

		Expect(logs("dns-repeats")).To(HaveLen(1))
		Expect(dataJSON(logs("dns-repeats")[0])).To(MatchJSON(`{
			"container": {"handle": "handle-1", "cgroup": "handle-1/init", "properties": {"network.app_id": "app-1", "app_name": "my-app"}},
			"host": {"ip": "10.0.73.1", "id": "cell-id"},
			"query": {"name": "beacon.example", "type": "A"},
			"repeats_suppressed": 1
		}`))
	})

	It("rate limits per container and summarises the dropped queries by suffix", func() {
		for _, name := range []string{"a.example", "b.example", "c.example", "x1.tunnel.example", "x2.tunnel.example", "y.other.org"} {
			processor.Handle(egress(queryPacket(1, 1, name)))
		}
		Expect(logs("dns-query")).To(HaveLen(3))
		Expect(processor.Counters.RateLimited.Load()).To(Equal(uint64(3)))

		processor.Tick()
		Expect(logs("dns-rate-limited")).To(BeEmpty(), "summaries are written once per window")

		clock.Advance(time.Minute)
		processor.Tick()
		Expect(logs("dns-rate-limited")).To(HaveLen(1))
		Expect(dataJSON(logs("dns-rate-limited")[0])).To(MatchJSON(`{
			"container": {"handle": "handle-1", "cgroup": "handle-1/init", "properties": {"network.app_id": "app-1", "app_name": "my-app"}},
			"host": {"ip": "10.0.73.1", "id": "cell-id"},
			"dropped": 3,
			"top_suffixes": [{"suffix": "tunnel.example", "count": 2}, {"suffix": "other.org", "count": 1}]
		}`))
	})

	It("doesn't report rate-limited queries as repeats of a line that wasn't written", func() {
		for _, name := range []string{"a.example", "b.example", "c.example", "d.example", "d.example"} {
			processor.Handle(egress(queryPacket(1, 1, name)))
		}
		Expect(logs("dns-query")).To(HaveLen(3))
		Expect(processor.Counters.RateLimited.Load()).To(Equal(uint64(2)))
		Expect(processor.Counters.QueriesSuppressed.Load()).To(BeZero())

		clock.Advance(time.Minute)
		processor.Tick()
		Expect(logs("dns-repeats")).To(BeEmpty())
		Expect(logs("dns-rate-limited")).To(HaveLen(1))
		Expect(logs("dns-rate-limited")[0].Data["dropped"]).To(BeNumerically("==", 2))
	})

	Context("with a cell limit", func() {
		other := identity.Container{Handle: "handle-2", Cgroup: "handle-2/init"}

		BeforeEach(func() {
			opts.CellRatePerSecond = 1
			opts.CellBurst = 2
			resolver.ResolveStub = func(id uint64) (identity.Container, bool) {
				switch id {
				case 42:
					return container, true
				case 43:
					return other, true
				}
				return identity.Container{}, false
			}
		})

		It("limits all containers together and reports the drops per container", func() {
			processor.Handle(egress(queryPacket(1, 1, "a.example")))
			processor.Handle(egress(queryPacket(1, 1, "b.example")))
			processor.Handle(audit.Event{CgroupID: 43, Time: captured, Direction: audit.Egress, Data: queryPacket(1, 1, "c.example")})

			Expect(logs("dns-query")).To(HaveLen(2))
			Expect(processor.Counters.RateLimited.Load()).To(Equal(uint64(1)))
			Expect(processor.Counters.RateLimitedCell.Load()).To(Equal(uint64(1)))

			clock.Advance(time.Minute)
			processor.Tick()
			Expect(logs("dns-rate-limited")).To(HaveLen(1))
			Expect(dataJSON(logs("dns-rate-limited")[0])).To(MatchJSON(`{
				"container": {"handle": "handle-2", "cgroup": "handle-2/init"},
				"host": {"ip": "10.0.73.1", "id": "cell-id"},
				"dropped": 1,
				"dropped_by_cell_limit": 1,
				"top_suffixes": [{"suffix": "c.example", "count": 1}]
			}`))
		})
	})

	Context("with response capture", func() {
		BeforeEach(func() {
			opts.CaptureResponses = true
		})

		It("waits for the response and logs its code with the query", func() {
			processor.Handle(egress(queryPacket(77, 5000, "c2.example")))
			Expect(logs("dns-query")).To(BeEmpty())
			Expect(processor.PendingLen()).To(Equal(1))

			processor.Handle(ingress(responsePacket(77, 5000, "C2.example", 3)))
			Expect(logs("dns-query")).To(HaveLen(1))
			Expect(logs("dns-query")[0].Data["response"]).To(Equal(map[string]interface{}{"received": true, "rcode": "NXDOMAIN"}))
			Expect(processor.Counters.ResponsesMatched.Load()).To(Equal(uint64(1)))
			Expect(processor.PendingLen()).To(BeZero())
		})

		It("only matches a response with the same ID, port and question", func() {
			processor.Handle(egress(queryPacket(77, 5000, "c2.example")))
			processor.Handle(ingress(responsePacket(78, 5000, "c2.example", 0)))
			processor.Handle(ingress(responsePacket(77, 5001, "c2.example", 0)))
			processor.Handle(ingress(responsePacket(77, 5000, "other.example", 0)))
			Expect(logs("dns-query")).To(BeEmpty())
			Expect(processor.Counters.ResponsesUnmatched.Load()).To(Equal(uint64(3)))
		})

		It("logs the query without a response after the timeout", func() {
			processor.Handle(egress(queryPacket(77, 5000, "slow.example")))
			clock.Advance(time.Second)
			processor.Tick()
			Expect(logs("dns-query")).To(BeEmpty())

			clock.Advance(time.Second)
			processor.Tick()
			Expect(logs("dns-query")).To(HaveLen(1))
			Expect(logs("dns-query")[0].Data["response"]).To(Equal(map[string]interface{}{"received": false}))
			Expect(processor.Counters.ResponsesTimedOut.Load()).To(Equal(uint64(1)))
		})

		It("logs immediately when too many queries are waiting", func() {
			opts.MaxPending = 1
			processor = audit.NewProcessor(opts, resolver, logger, clock.Now)
			processor.Handle(egress(queryPacket(1, 5000, "a.example")))
			processor.Handle(egress(queryPacket(2, 5000, "b.example")))
			Expect(logs("dns-query")).To(HaveLen(1))
			Expect(processor.Counters.PendingFull.Load()).To(Equal(uint64(1)))
		})

		It("writes everything still waiting on Flush", func() {
			processor.Handle(egress(queryPacket(1, 5000, "a.example")))
			processor.Handle(egress(queryPacket(2, 5000, "a.example")))
			processor.Flush()
			Expect(logs("dns-query")).To(HaveLen(1))
			Expect(logs("dns-repeats")).To(HaveLen(1))
		})
	})

	It("ignores responses when response capture is off", func() {
		processor.Handle(egress(queryPacket(77, 5000, "a.example")))
		processor.Handle(ingress(responsePacket(77, 5000, "a.example", 3)))
		Expect(logs("dns-query")).To(HaveLen(1))
		Expect(logs("dns-query")[0].Data).NotTo(HaveKey("response"))
	})
})
