//go:build linux

package integration_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var (
	daemonPath   string
	clientPath   string
	attachedPath string
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "DNS Audit Integration Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	paths := map[string]string{}
	for name, pkg := range map[string]string{
		"daemon":   "code.cloudfoundry.org/guardian/cmd/dns-audit",
		"client":   "code.cloudfoundry.org/guardian/dnsaudit/testassets/dnsclient",
		"attached": "code.cloudfoundry.org/guardian/dnsaudit/testassets/attached",
	} {
		path, err := gexec.Build(pkg, "-buildvcs=false")
		Expect(err).NotTo(HaveOccurred())
		paths[name] = path
	}
	data, err := json.Marshal(paths)
	Expect(err).NotTo(HaveOccurred())
	return data
}, func(data []byte) {
	paths := map[string]string{}
	Expect(json.Unmarshal(data, &paths)).To(Succeed())
	daemonPath, clientPath, attachedPath = paths["daemon"], paths["client"], paths["attached"]
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
})

// fakeGarden serves the two Garden API endpoints dns-audit uses.
type fakeGarden struct {
	server     *http.Server
	listener   net.Listener
	mu         sync.Mutex
	properties map[string]map[string]string
}

func startFakeGarden(socket string, properties map[string]map[string]string) *fakeGarden {
	g := &fakeGarden{properties: properties}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /containers", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		handles := []string{}
		for h := range g.properties {
			handles = append(handles, h)
		}
		_ = json.NewEncoder(w).Encode(map[string][]string{"Handles": handles})
	})
	mux.HandleFunc("GET /containers/{handle}/properties", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		props, ok := g.properties[r.PathValue("handle")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"Type": "ContainerNotFoundError", "Message": "unknown handle"})
			return
		}
		_ = json.NewEncoder(w).Encode(props)
	})

	listener, err := net.Listen("unix", socket)
	Expect(err).NotTo(HaveOccurred())
	g.listener = listener
	g.server = &http.Server{Handler: mux}
	go func() { _ = g.server.Serve(listener) }()
	return g
}

func (g *fakeGarden) Stop() {
	_ = g.server.Close()
}

// fakeDNS answers every UDP and TCP query with the question, NXDOMAIN for
// names starting with "nx", NOERROR otherwise.
type fakeDNS struct {
	udp *net.UDPConn
	tcp *net.TCPListener
}

func startFakeDNS(ip string) *fakeDNS {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip), Port: 53})
	Expect(err).NotTo(HaveOccurred())
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(ip), Port: 53})
	Expect(err).NotTo(HaveOccurred())

	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(answer(buf[:n]), addr)
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				header := make([]byte, 2)
				if _, err := conn.Read(header); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(header))
				if _, err := conn.Read(msg); err != nil {
					return
				}
				reply := answer(msg)
				_, _ = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...))
			}()
		}
	}()
	return &fakeDNS{udp: udp, tcp: tcp}
}

func answer(query []byte) []byte {
	if len(query) < 13 {
		return nil
	}
	reply := append([]byte{}, query...)
	rcode := byte(0)
	if strings.HasPrefix(strings.ToLower(string(query[13:15])), "nx") {
		rcode = 3
	}
	reply[2] |= 0x80
	reply[3] = 0x80 | rcode
	return reply
}

func (d *fakeDNS) Stop() {
	_ = d.udp.Close()
	_ = d.tcp.Close()
}

func cgroup2Available() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

func makeCgroup(parts ...string) string {
	path := filepath.Join(parts...)
	Expect(os.MkdirAll(path, 0755)).To(Succeed())
	return path
}

// removeCgroups removes a cgroup tree bottom-up; cgroup directories can only
// be removed with rmdir once empty.
func removeCgroups(root string) {
	var dirs []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Remove(dirs[i])
	}
}

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d-%d.it.example", prefix, GinkgoParallelProcess(), GinkgoRandomSeed())
}
