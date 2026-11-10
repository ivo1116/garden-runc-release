package audit_test

import (
	"encoding/binary"
	"net"
)

func wireName(name string) []byte {
	var b []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			b = append(b, byte(i-start))
			b = append(b, name[start:i]...)
			start = i + 1
		}
	}
	return append(b, 0)
}

func dnsMessage(id, flags uint16, name string, qtype uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], flags)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, wireName(name)...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	return binary.BigEndian.AppendUint16(msg, 1)
}

func udpPacket(src, dst string, srcPort, dstPort uint16, payload []byte) []byte {
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:2], srcPort)
	binary.BigEndian.PutUint16(l4[2:4], dstPort)
	binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
	l4 = append(l4, payload...)

	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+len(l4)))
	h[9] = 17
	copy(h[12:16], net.ParseIP(src).To4())
	copy(h[16:20], net.ParseIP(dst).To4())
	return append(h, l4...)
}

func queryPacket(id uint16, port uint16, name string) []byte {
	return udpPacket("10.255.0.1", "169.254.0.53", port, 53, dnsMessage(id, 0x0100, name, 1))
}

func responsePacket(id uint16, port uint16, name string, rcode uint16) []byte {
	return udpPacket("169.254.0.53", "10.255.0.1", 53, port, dnsMessage(id, 0x8180|rcode, name, 1))
}
