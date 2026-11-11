package decode_test

import (
	"strings"
	"testing"

	"code.cloudfoundry.org/guardian/dnsaudit/decode"
)

func FuzzDecode(f *testing.F) {
	seeds := [][]byte{
		udpQuery(query(1, wireName("example", "com"), 1)),
		udpQuery(query(1, wireName("a.b", "example"), 1)),
		udpQuery(query(1, wireName("\x00\xff ", "example"), 28)),
		udpQuery(query(1, []byte{1, 'a', 0xc0, 12}, 1)),
		udpQuery(query(1, []byte{0}, 2)),
		ipv4(17, "169.254.0.53", "10.0.0.1", udp(53, 4000, response(1, 3, wireName("example"), 1)), ipOptions{}),
		ipv4(6, "10.0.0.1", "10.0.0.2", tcp(4000, 53, tcpMessage(query(1, wireName("example", "com"), 16))), ipOptions{}),
		ipv4(6, "10.0.0.1", "10.0.0.2", tcp(4000, 53, nil), ipOptions{}),
		ipv6(17, "fd00::1", "fd00::2", udp(4000, 53, query(1, wireName("example"), 28))),
		ipv4(17, "10.0.0.1", "10.0.0.2", udp(4000, 53, query(1, wireName("x"), 1)), ipOptions{ihlWords: 15}),
		{0x45},
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pkt []byte) {
		m, reason := decode.Decode(pkt)
		if reason != decode.ReasonOK {
			if m != (decode.Message{}) {
				t.Fatalf("non-empty message for reason %s: %+v", reason, m)
			}
			return
		}
		if m.Name == "" {
			t.Fatal("empty name")
		}
		for i := 0; i < len(m.Name); i++ {
			if m.Name[i] < 0x21 || m.Name[i] > 0x7e {
				t.Fatalf("name contains non-printable byte %#x: %q", m.Name[i], m.Name)
			}
		}
		if strings.ToLower(m.Name) != m.Name {
			t.Fatalf("name is not lowercase: %q", m.Name)
		}
		if m.Response != (m.RCode != "") {
			t.Fatalf("response %v with rcode %q", m.Response, m.RCode)
		}
		_ = decode.Suffix(m.Name)
	})
}
