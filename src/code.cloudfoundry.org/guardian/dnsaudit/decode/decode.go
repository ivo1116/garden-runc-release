// Package decode parses DNS messages captured from the network layer. All
// input is untrusted: every read is bounds-checked and errors are reported as
// a Reason instead of panicking.
package decode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

type Reason int

const (
	ReasonOK Reason = iota
	ReasonIgnored
	ReasonMalformed
	ReasonUnsupported
	ReasonNotQuery
)

func (r Reason) String() string {
	switch r {
	case ReasonOK:
		return "ok"
	case ReasonIgnored:
		return "ignored"
	case ReasonMalformed:
		return "malformed"
	case ReasonUnsupported:
		return "unsupported"
	case ReasonNotQuery:
		return "not_query"
	}
	return fmt.Sprintf("reason(%d)", int(r))
}

type Message struct {
	Family   string
	Protocol string
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	ID       uint16
	Response bool
	RCode    string
	Name     string
	Type     string
}

const (
	protoTCP = 6
	protoUDP = 17

	headerLength      = 12
	maxNameWireLength = 255
	maxLabelLength    = 63
	maxPointerHops    = 10
)

var (
	errShort          = errors.New("name exceeds message")
	errLabelTooLong   = errors.New("label too long")
	errNameTooLong    = errors.New("name too long")
	errBadPointer     = errors.New("compression pointer does not point backwards")
	errTooManyHops    = errors.New("too many compression pointers")
	errReservedPrefix = errors.New("reserved label prefix")
)

// Decode parses an IPv4 or IPv6 packet carrying a DNS message over UDP or TCP
// and returns the header fields and the first question. pkt starts at the IP
// header and may be shorter than the packet (capture length).
func Decode(pkt []byte) (Message, Reason) {
	if len(pkt) < 1 {
		return Message{}, ReasonMalformed
	}

	var m Message
	var proto byte
	var l4 []byte
	truncated := false

	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return Message{}, ReasonMalformed
		}
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if ihl < 20 || len(pkt) < ihl || total < ihl {
			return Message{}, ReasonMalformed
		}
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
			return Message{}, ReasonUnsupported
		}
		if total < len(pkt) {
			pkt = pkt[:total]
		} else if total > len(pkt) {
			truncated = true
		}
		m.Family = "ipv4"
		m.SrcIP = net.IP(pkt[12:16]).String()
		m.DstIP = net.IP(pkt[16:20]).String()
		proto = pkt[9]
		l4 = pkt[ihl:]
	case 6:
		if len(pkt) < 40 {
			return Message{}, ReasonMalformed
		}
		total := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		if total < len(pkt) {
			pkt = pkt[:total]
		} else if total > len(pkt) {
			truncated = true
		}
		m.Family = "ipv6"
		m.SrcIP = net.IP(pkt[8:24]).String()
		m.DstIP = net.IP(pkt[24:40]).String()
		proto = pkt[6]
		l4 = pkt[40:]
	default:
		return Message{}, ReasonMalformed
	}

	var msg []byte
	switch proto {
	case protoUDP:
		if len(l4) < 8 {
			return Message{}, ReasonMalformed
		}
		m.Protocol = "udp"
		m.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		m.DstPort = binary.BigEndian.Uint16(l4[2:4])
		msg = l4[8:]
		if udpLength := int(binary.BigEndian.Uint16(l4[4:6])); udpLength >= 8 && udpLength < len(l4) {
			msg = l4[8:udpLength]
		}
	case protoTCP:
		if len(l4) < 20 {
			return Message{}, ReasonMalformed
		}
		dataOffset := int(l4[12]>>4) * 4
		if dataOffset < 20 || len(l4) < dataOffset {
			return Message{}, ReasonMalformed
		}
		m.Protocol = "tcp"
		m.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		m.DstPort = binary.BigEndian.Uint16(l4[2:4])
		payload := l4[dataOffset:]
		if len(payload) == 0 {
			return Message{}, ReasonIgnored
		}
		if len(payload) < 2 {
			return Message{}, ReasonUnsupported
		}
		length := int(binary.BigEndian.Uint16(payload[0:2]))
		msg = payload[2:]
		if length < len(msg) {
			msg = msg[:length]
		} else if length > len(msg) {
			truncated = true
		}
	default:
		return Message{}, ReasonUnsupported
	}

	return decodeMessage(msg, m, truncated)
}

// decodeMessage parses the DNS header and the first question. When the message
// continues beyond the captured bytes, running out of bytes is reported as
// unsupported rather than malformed.
func decodeMessage(msg []byte, m Message, truncated bool) (Message, Reason) {
	short := ReasonMalformed
	if truncated {
		short = ReasonUnsupported
	}
	if len(msg) < headerLength {
		return Message{}, short
	}

	flags := binary.BigEndian.Uint16(msg[2:4])
	if (flags>>11)&0x0f != 0 {
		return Message{}, ReasonNotQuery
	}
	if binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return Message{}, ReasonNotQuery
	}

	name, off, err := readName(msg, headerLength)
	if err != nil {
		if errors.Is(err, errShort) {
			return Message{}, short
		}
		return Message{}, ReasonMalformed
	}
	if len(msg) < off+4 {
		return Message{}, short
	}

	m.ID = binary.BigEndian.Uint16(msg[0:2])
	m.Response = flags&0x8000 != 0
	if m.Response {
		m.RCode = RCodeName(flags & 0x0f)
	}
	m.Name = name
	m.Type = TypeName(binary.BigEndian.Uint16(msg[off : off+2]))
	return m, ReasonOK
}

// readName reads a domain name starting at off and returns it in presentation
// format (lowercase, no trailing dot, escaped like dig) together with the
// offset of the first byte after the name.
func readName(msg []byte, off int) (string, int, error) {
	var b strings.Builder
	end := -1
	hops := 0
	wireLength := 1
	labels := 0

	for {
		if off >= len(msg) {
			return "", 0, errShort
		}
		c := int(msg[off])
		switch c & 0xc0 {
		case 0x00:
			off++
			if c == 0 {
				if end < 0 {
					end = off
				}
				if labels == 0 {
					return ".", end, nil
				}
				return b.String(), end, nil
			}
			if c > maxLabelLength {
				return "", 0, errLabelTooLong
			}
			if off+c > len(msg) {
				return "", 0, errShort
			}
			wireLength += c + 1
			if wireLength > maxNameWireLength {
				return "", 0, errNameTooLong
			}
			if labels > 0 {
				b.WriteByte('.')
			}
			writeLabel(&b, msg[off:off+c])
			labels++
			off += c
		case 0xc0:
			if off+1 >= len(msg) {
				return "", 0, errShort
			}
			ptr := (c&0x3f)<<8 | int(msg[off+1])
			if end < 0 {
				end = off + 2
			}
			if ptr >= off {
				return "", 0, errBadPointer
			}
			hops++
			if hops > maxPointerHops {
				return "", 0, errTooManyHops
			}
			off = ptr
		default:
			return "", 0, errReservedPrefix
		}
	}
}

func writeLabel(b *strings.Builder, label []byte) {
	for _, c := range label {
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case c == '.' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x21 || c > 0x7e:
			fmt.Fprintf(b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
}

var typeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
	16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS",
	46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 52: "TLSA",
	64: "SVCB", 65: "HTTPS", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY",
	257: "CAA",
}

func TypeName(t uint16) string {
	if name, ok := typeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

var rcodeNames = map[uint16]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
	5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
	10: "NOTZONE",
}

func RCodeName(rcode uint16) string {
	if name, ok := rcodeNames[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

// Suffix returns the last two labels of an escaped name, or the name itself
// when it has fewer labels.
func Suffix(name string) string {
	dots := 0
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' && !Escaped(name, i) {
			dots++
			if dots == 2 {
				return name[i+1:]
			}
		}
	}
	return name
}

// Escaped reports whether the byte at i is preceded by an odd number of
// backslashes, i.e. is part of a label rather than a separator.
func Escaped(name string, i int) bool {
	backslashes := 0
	for j := i - 1; j >= 0 && name[j] == '\\'; j-- {
		backslashes++
	}
	return backslashes%2 == 1
}
