// dnsclient sends one DNS query and waits briefly for the response. It is
// started inside a test cgroup by the integration tests.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

var types = map[string]uint16{"A": 1, "TXT": 16, "AAAA": 28}

func main() {
	server := flag.String("server", "127.0.0.1", "DNS server address")
	name := flag.String("name", "example.com", "name to query; \\. is a dot inside a label")
	qtype := flag.String("type", "A", "query type")
	proto := flag.String("proto", "udp", "udp, tcp or raw (spoofed source address)")
	spoofSource := flag.String("spoof-source", "", "source address for -proto raw")
	padding := flag.Int("padding", 0, "bytes appended after the question")
	id := flag.Int("id", 4242, "query ID")
	flag.Parse()

	msg := query(uint16(*id), *name, types[*qtype])
	msg = append(msg, make([]byte, *padding)...)

	var err error
	switch *proto {
	case "udp":
		err = sendUDP(*server, msg)
	case "tcp":
		err = sendTCP(*server, msg)
	case "raw":
		err = sendRaw(*spoofSource, *server, msg)
	default:
		err = fmt.Errorf("unknown protocol %q", *proto)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func query(id uint16, name string, qtype uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, label := range splitLabels(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	return binary.BigEndian.AppendUint16(msg, 1)
}

func splitLabels(name string) []string {
	var labels []string
	var current strings.Builder
	for i := 0; i < len(name); i++ {
		switch {
		case name[i] == '\\' && i+1 < len(name):
			i++
			current.WriteByte(name[i])
		case name[i] == '.':
			labels = append(labels, current.String())
			current.Reset()
		default:
			current.WriteByte(name[i])
		}
	}
	return append(labels, current.String())
}

func sendUDP(server string, msg []byte) error {
	conn, err := net.Dial("udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	_, _ = conn.Read(buf)
	return nil
}

func sendTCP(server string, msg []byte) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, "53"), time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	_, _ = conn.Read(buf)
	return nil
}

// sendRaw sends an IPv4/UDP packet with a forged source address through a
// raw socket.
func sendRaw(source, server string, msg []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(msg)))
	udp = append(udp, msg...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udp)))
	ip[8] = 64
	ip[9] = syscall.IPPROTO_UDP
	copy(ip[12:16], net.ParseIP(source).To4())
	dst := net.ParseIP(server).To4()
	copy(ip[16:20], dst)

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dst)
	return syscall.Sendto(fd, append(ip, udp...), 0, &addr)
}
