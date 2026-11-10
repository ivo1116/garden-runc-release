package decode_test

import (
	"strings"

	"code.cloudfoundry.org/guardian/dnsaudit/decode"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Decode", func() {
	It("decodes an IPv4 UDP query", func() {
		m, reason := decode.Decode(udpQuery(query(51812, wireName("example", "com"), 1)))
		Expect(reason).To(Equal(decode.ReasonOK))
		Expect(m).To(Equal(decode.Message{
			Family:   "ipv4",
			Protocol: "udp",
			SrcIP:    "10.255.0.1",
			DstIP:    "169.254.0.53",
			SrcPort:  41234,
			DstPort:  53,
			ID:       51812,
			Name:     "example.com",
			Type:     "A",
		}))
	})

	It("decodes an IPv6 UDP query", func() {
		m, reason := decode.Decode(ipv6(17, "fd00::1", "fd00::53", udp(5000, 53, query(1, wireName("example", "com"), 28))))
		Expect(reason).To(Equal(decode.ReasonOK))
		Expect(m.Family).To(Equal("ipv6"))
		Expect(m.SrcIP).To(Equal("fd00::1"))
		Expect(m.DstIP).To(Equal("fd00::53"))
		Expect(m.Type).To(Equal("AAAA"))
	})

	It("decodes a TCP query in one segment", func() {
		m, reason := decode.Decode(ipv4(6, "10.0.0.1", "10.0.0.2", tcp(4000, 53, tcpMessage(query(7, wireName("example", "com"), 16))), ipOptions{}))
		Expect(reason).To(Equal(decode.ReasonOK))
		Expect(m.Protocol).To(Equal("tcp"))
		Expect(m.Type).To(Equal("TXT"))
		Expect(m.ID).To(Equal(uint16(7)))
	})

	DescribeTable("responses",
		func(rcode uint16, expected string) {
			m, reason := decode.Decode(ipv4(17, "169.254.0.53", "10.255.0.1", udp(53, 41234, response(9, rcode, wireName("example", "com"), 1)), ipOptions{}))
			Expect(reason).To(Equal(decode.ReasonOK))
			Expect(m.Response).To(BeTrue())
			Expect(m.RCode).To(Equal(expected))
			Expect(m.Name).To(Equal("example.com"))
			Expect(m.SrcPort).To(Equal(uint16(53)))
			Expect(m.DstPort).To(Equal(uint16(41234)))
		},
		Entry("NOERROR", uint16(0), "NOERROR"),
		Entry("SERVFAIL", uint16(2), "SERVFAIL"),
		Entry("NXDOMAIN", uint16(3), "NXDOMAIN"),
		Entry("REFUSED", uint16(5), "REFUSED"),
		Entry("unknown", uint16(15), "RCODE15"),
	)

	It("has no response code for queries", func() {
		m, _ := decode.Decode(udpQuery(query(1, wireName("example"), 1)))
		Expect(m.Response).To(BeFalse())
		Expect(m.RCode).To(BeEmpty())
	})

	DescribeTable("query types",
		func(qtype uint16, expected string) {
			m, reason := decode.Decode(udpQuery(query(1, wireName("example", "com"), qtype)))
			Expect(reason).To(Equal(decode.ReasonOK))
			Expect(m.Type).To(Equal(expected))
		},
		Entry("A", uint16(1), "A"),
		Entry("AAAA", uint16(28), "AAAA"),
		Entry("TXT", uint16(16), "TXT"),
		Entry("HTTPS", uint16(65), "HTTPS"),
		Entry("unknown", uint16(65280), "TYPE65280"),
	)

	It("ignores TCP segments without payload", func() {
		_, reason := decode.Decode(ipv4(6, "10.0.0.1", "10.0.0.2", tcp(4000, 53, nil), ipOptions{}))
		Expect(reason).To(Equal(decode.ReasonIgnored))
	})

	It("reports a TCP message that continues in a later segment as unsupported", func() {
		payload := tcpMessage(query(7, wireName("example", "com"), 1))[:7]
		_, reason := decode.Decode(ipv4(6, "10.0.0.1", "10.0.0.2", tcp(4000, 53, payload), ipOptions{}))
		Expect(reason).To(Equal(decode.ReasonUnsupported))
	})

	It("decodes a question from a capture that is shorter than the packet", func() {
		msg := append(query(1, wireName("example", "com"), 1), make([]byte, 3000)...)
		pkt := ipv4(17, "10.0.0.1", "10.0.0.2", udp(4000, 53, msg), ipOptions{})
		m, reason := decode.Decode(pkt[:640])
		Expect(reason).To(Equal(decode.ReasonOK))
		Expect(m.Name).To(Equal("example.com"))
	})

	It("reports a capture that ends inside the question as unsupported", func() {
		pkt := udpQuery(query(1, wireName(strings.Repeat("a", 60), "example", "com"), 1))
		_, reason := decode.Decode(pkt[:50])
		Expect(reason).To(Equal(decode.ReasonUnsupported))
	})

	It("handles IPv4 options and link-layer padding", func() {
		pkt := ipv4(17, "10.0.0.1", "10.0.0.2", udp(4000, 53, query(1, wireName("example", "com"), 1)), ipOptions{ihlWords: 6, trailer: make([]byte, 20)})
		m, reason := decode.Decode(pkt)
		Expect(reason).To(Equal(decode.ReasonOK))
		Expect(m.Name).To(Equal("example.com"))
	})

	It("decodes a first fragment", func() {
		pkt := ipv4(17, "10.0.0.1", "10.0.0.2", udp(4000, 53, query(1, wireName("example", "com"), 1)), ipOptions{fragment: moreFragments})
		_, reason := decode.Decode(pkt)
		Expect(reason).To(Equal(decode.ReasonOK))
	})

	DescribeTable("unsupported packets",
		func(pkt []byte) {
			_, reason := decode.Decode(pkt)
			Expect(reason).To(Equal(decode.ReasonUnsupported))
		},
		Entry("later fragment", ipv4(17, "10.0.0.1", "10.0.0.2", udp(4000, 53, nil), ipOptions{fragment: 100})),
		Entry("ICMP", ipv4(1, "10.0.0.1", "10.0.0.2", make([]byte, 8), ipOptions{})),
		Entry("IPv6 extension header", ipv6(0, "fd00::1", "fd00::2", make([]byte, 40))),
	)

	DescribeTable("messages that are not standard queries or responses",
		func(msg []byte) {
			_, reason := decode.Decode(udpQuery(msg))
			Expect(reason).To(Equal(decode.ReasonNotQuery))
		},
		Entry("update", message(1, opcodeUpdate, 1, question(wireName("example"), 1))),
		Entry("no questions", message(1, flagRD, 0, nil)),
	)

	DescribeTable("malformed packets",
		func(pkt []byte) {
			_, reason := decode.Decode(pkt)
			Expect(reason).To(Equal(decode.ReasonMalformed))
		},
		Entry("empty", []byte{}),
		Entry("short IPv4", []byte{0x45, 1, 2, 3}),
		Entry("short IPv6", append([]byte{0x60}, make([]byte, 20)...)),
		Entry("unknown IP version", append([]byte{0x75}, make([]byte, 40)...)),
		Entry("IHL below minimum", func() []byte {
			pkt := udpQuery(query(1, wireName("example"), 1))
			pkt[0] = 0x44
			return pkt
		}()),
		Entry("short UDP header", ipv4(17, "10.0.0.1", "10.0.0.2", []byte{0, 53, 0}, ipOptions{})),
		Entry("short TCP header", ipv4(6, "10.0.0.1", "10.0.0.2", make([]byte, 10), ipOptions{})),
		Entry("short DNS header", udpQuery([]byte{1, 2, 3})),
		Entry("name exceeds message", udpQuery(message(1, flagRD, 1, []byte{7, 'e', 'x'}))),
		Entry("missing type and class", udpQuery(message(1, flagRD, 1, wireName("example", "com")))),
		Entry("label longer than 63", udpQuery(query(1, wireName(strings.Repeat("a", 64), "com"), 1))),
		Entry("name longer than 255", udpQuery(query(1, wireName(strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 63)), 1))),
		Entry("reserved label prefix", udpQuery(query(1, []byte{0x40, 'a', 0}, 1))),
		Entry("forward pointer", udpQuery(query(1, []byte{0xc0, 20}, 1))),
		Entry("self pointer", udpQuery(query(1, []byte{0xc0, 12}, 1))),
		Entry("pointer loop", udpQuery(query(1, []byte{1, 'a', 0xc0, 12}, 1))),
	)

	It("accepts a name of exactly 255 bytes on the wire", func() {
		name := wireName(strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61))
		Expect(name).To(HaveLen(255))
		m, reason := decode.Decode(udpQuery(query(1, name, 1)))
		Expect(reason).To(Equal(decode.ReasonOK))
		Expect(m.Name).To(HaveLen(253))
	})

	It("follows a backward compression pointer", func() {
		msg := message(0, 0, 1, nil)
		msg[0], msg[1] = 1, 'x'
		msg = append(msg, 3, 'w', 'w', 'w', 0xc0, 0, 0, 1, 0, 1)
		m, reason := decode.Decode(udpQuery(msg))
		Expect(reason).To(Equal(decode.ReasonOK))
		Expect(m.Name).To(Equal("www.x"))
	})

	It("decodes the root name", func() {
		m, reason := decode.Decode(udpQuery(query(1, []byte{0}, 2)))
		Expect(reason).To(Equal(decode.ReasonOK))
		Expect(m.Name).To(Equal("."))
		Expect(m.Type).To(Equal("NS"))
	})

	DescribeTable("name escaping",
		func(name []byte, expected string) {
			m, reason := decode.Decode(udpQuery(query(1, name, 1)))
			Expect(reason).To(Equal(decode.ReasonOK))
			Expect(m.Name).To(Equal(expected))
		},
		Entry("uppercase", wireName("WWW", "Example", "COM"), "www.example.com"),
		Entry("dot inside a label", wireName("a.b", "example", "com"), `a\.b.example.com`),
		Entry("backslash inside a label", wireName(`a\b`, "example"), `a\\b.example`),
		Entry("space", wireName("a b", "example"), `a\032b.example`),
		Entry("control byte", wireName("a\x00b", "example"), `a\000b.example`),
		Entry("non-ASCII byte", wireName("caf\xe9", "example"), `caf\233.example`),
		Entry("printable punctuation", wireName(`_a-b"c`, "example"), `_a-b"c.example`),
	)
})

var _ = Describe("Suffix", func() {
	DescribeTable("returns the last two labels",
		func(name, expected string) {
			Expect(decode.Suffix(name)).To(Equal(expected))
		},
		Entry("long name", "a.b.example.com", "example.com"),
		Entry("two labels", "example.com", "example.com"),
		Entry("one label", "localhost", "localhost"),
		Entry("root", ".", "."),
		Entry("escaped dot", `x.a\.b.example`, `a\.b.example`),
		Entry("escaped backslash before a dot", `x.a\\.example`, `a\\.example`),
	)
})
