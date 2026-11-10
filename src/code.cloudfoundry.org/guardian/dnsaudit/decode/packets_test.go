package decode_test

import (
	"encoding/binary"
	"net"
)

const (
	flagQR        = 0x8000
	flagRD        = 0x0100
	opcodeUpdate  = 5 << 11
	moreFragments = 0x2000
)

func wireName(labels ...string) []byte {
	var b []byte
	for _, l := range labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func message(id, flags, qdcount uint16, body []byte) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], flags)
	binary.BigEndian.PutUint16(msg[4:6], qdcount)
	return append(msg, body...)
}

func question(name []byte, qtype uint16) []byte {
	q := append([]byte{}, name...)
	q = binary.BigEndian.AppendUint16(q, qtype)
	return binary.BigEndian.AppendUint16(q, 1)
}

func query(id uint16, name []byte, qtype uint16) []byte {
	return message(id, flagRD, 1, question(name, qtype))
}

func response(id uint16, rcode uint16, name []byte, qtype uint16) []byte {
	return message(id, flagQR|flagRD|rcode, 1, question(name, qtype))
}

type ipOptions struct {
	ihlWords int
	fragment uint16
	trailer  []byte
}

func ipv4(proto byte, src, dst string, l4 []byte, opts ipOptions) []byte {
	ihl := 20
	if opts.ihlWords > 0 {
		ihl = opts.ihlWords * 4
	}
	h := make([]byte, ihl)
	h[0] = 4<<4 | byte(ihl/4)
	binary.BigEndian.PutUint16(h[2:4], uint16(ihl+len(l4)))
	binary.BigEndian.PutUint16(h[6:8], opts.fragment)
	h[8] = 64
	h[9] = proto
	copy(h[12:16], net.ParseIP(src).To4())
	copy(h[16:20], net.ParseIP(dst).To4())
	return append(append(h, l4...), opts.trailer...)
}

func ipv6(nextHeader byte, src, dst string, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0] = 6 << 4
	binary.BigEndian.PutUint16(h[4:6], uint16(len(l4)))
	h[6] = nextHeader
	h[7] = 64
	copy(h[8:24], net.ParseIP(src).To16())
	copy(h[24:40], net.ParseIP(dst).To16())
	return append(h, l4...)
}

func udp(srcPort, dstPort uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	binary.BigEndian.PutUint16(h[4:6], uint16(8+len(payload)))
	return append(h, payload...)
}

func tcp(srcPort, dstPort uint16, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	h[12] = 5 << 4
	h[13] = 0x18
	return append(h, payload...)
}

func tcpMessage(msg []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
}

func udpQuery(msg []byte) []byte {
	return ipv4(17, "10.255.0.1", "169.254.0.53", udp(41234, 53, msg), ipOptions{})
}
