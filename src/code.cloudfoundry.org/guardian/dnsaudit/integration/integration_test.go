//go:build linux

package integration_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

type logLine struct {
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
}

var _ = Describe("dns-audit", func() {
	var (
		tmpDir      string
		cgroupRoot  string
		dnsLog      string
		serverIP    string
		garden      *fakeGarden
		dns         *fakeDNS
		session     *gexec.Session
		cfg         map[string]interface{}
		logConfig   string
		handle1Init string
		handle2Init string
		healthcheck string
		waitStart   bool
	)

	BeforeEach(func() {
		if os.Geteuid() != 0 || !cgroup2Available() {
			Skip("requires root and cgroup v2")
		}

		var err error
		waitStart = true
		tmpDir, err = os.MkdirTemp("", "dns-audit-it")
		Expect(err).NotTo(HaveOccurred())

		proc := GinkgoParallelProcess()
		cgroupRoot = makeCgroup("/sys/fs/cgroup", fmt.Sprintf("dns-audit-it-%d", proc))
		handle1Init = makeCgroup(cgroupRoot, "handle-1", "init")
		handle2Init = makeCgroup(cgroupRoot, "handle-2", "init")
		healthcheck = makeCgroup(cgroupRoot, "handle-1-liveness-healthcheck-0")

		logConfig = `{"guid":"app-1","index":0,"source_name":"CELL","tags":{"app_name":"app-one","space_name":"space-one","organization_name":"org-one","instance_id":"0"}}`
		garden = startFakeGarden(filepath.Join(tmpDir, "garden.sock"), map[string]map[string]string{
			"handle-1": {"network.app_id": "app-1", "network.space_id": "space-1", "log_config": logConfig},
			"handle-2": {"network.app_id": "app-2", "network.space_id": "space-2"},
		})

		serverIP = fmt.Sprintf("127.%d.0.53", 10+proc)
		dns = startFakeDNS(serverIP)

		dnsLog = filepath.Join(tmpDir, "dns.log")
		cfg = map[string]interface{}{
			"enabled":                           true,
			"cgroup_root":                       cgroupRoot,
			"garden_address":                    filepath.Join(tmpDir, "garden.sock"),
			"output_log_file":                   dnsLog,
			"host_ip":                           "10.0.0.5",
			"host_id":                           "cell-id",
			"properties":                        []string{"network.app_id", "app_name", "space_name"},
			"dedup_window_seconds":              2,
			"max_logs_per_second_per_container": 2,
			"exclude_domains":                   []string{"excluded.it.example"},
			"capture_responses":                 true,
			"response_timeout_millis":           500,
			"metrics_interval_seconds":          1,
		}
	})

	JustBeforeEach(func() {
		configPath := filepath.Join(tmpDir, "config.json")
		contents, err := json.Marshal(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(configPath, contents, 0644)).To(Succeed())

		session, err = gexec.Start(exec.Command(daemonPath, "-config", configPath), GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		if waitStart {
			Eventually(session, "10s").Should(gbytes.Say("dns-audit.started"))
		}
	})

	AfterEach(func() {
		if session != nil {
			session.Terminate()
			Eventually(session, "10s").Should(gexec.Exit())
		}
		if dns != nil {
			dns.Stop()
		}
		if garden != nil {
			garden.Stop()
		}
		removeCgroups(cgroupRoot)
		os.RemoveAll(tmpDir)
	})

	runIn := func(cgroup string, args ...string) {
		dir, err := os.Open(cgroup)
		Expect(err).NotTo(HaveOccurred())
		defer dir.Close()

		cmd := exec.Command(clientPath, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
	}

	readLog := func() []logLine {
		contents, err := os.ReadFile(dnsLog)
		if err != nil {
			return nil
		}
		var lines []logLine
		for _, raw := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
			if raw == "" {
				continue
			}
			var l logLine
			Expect(json.Unmarshal([]byte(raw), &l)).To(Succeed())
			lines = append(lines, l)
		}
		return lines
	}

	queries := func(name string) func() []logLine {
		return func() []logLine {
			var out []logLine
			for _, l := range readLog() {
				query, _ := l.Data["query"].(map[string]interface{})
				if l.Message == "garden.dns-audit.dns-query" && query["name"] == name {
					out = append(out, l)
				}
			}
			return out
		}
	}

	It("logs a UDP query with the container, its properties and the response code", func() {
		name := uniqueName("nx-udp")
		runIn(handle1Init, "-server", serverIP, "-name", name, "-type", "AAAA")

		Eventually(queries(name), "5s").Should(HaveLen(1))
		line := queries(name)()[0]
		Expect(line.Data["container"]).To(Equal(map[string]interface{}{
			"handle": "handle-1",
			"cgroup": "handle-1/init",
			"properties": map[string]interface{}{
				"network.app_id": "app-1",
				"app_name":       "app-one",
				"space_name":     "space-one",
			},
		}))
		Expect(line.Data["host"]).To(Equal(map[string]interface{}{"ip": "10.0.0.5", "id": "cell-id"}))
		Expect(line.Data["response"]).To(Equal(map[string]interface{}{"received": true, "rcode": "NXDOMAIN"}))
		query := line.Data["query"].(map[string]interface{})
		Expect(query).To(HaveKeyWithValue("type", "AAAA"))
		Expect(query).To(HaveKeyWithValue("protocol", "udp"))
		Expect(query).To(HaveKeyWithValue("family", "ipv4"))
		Expect(query).To(HaveKeyWithValue("dst_ip", serverIP))
		Expect(query).To(HaveKeyWithValue("dst_port", BeNumerically("==", 53)))
		Expect(query).To(HaveKeyWithValue("id", BeNumerically("==", 4242)))
		Consistently(queries(name), "500ms").Should(HaveLen(1))
	})

	It("logs a TCP query", func() {
		name := uniqueName("tcp")
		runIn(handle2Init, "-server", serverIP, "-name", name, "-type", "TXT", "-proto", "tcp")

		Eventually(queries(name), "5s").Should(HaveLen(1))
		line := queries(name)()[0]
		Expect(line.Data["container"]).To(HaveKeyWithValue("handle", "handle-2"))
		Expect(line.Data["query"]).To(HaveKeyWithValue("protocol", "tcp"))
		Expect(line.Data["response"]).To(Equal(map[string]interface{}{"received": true, "rcode": "NOERROR"}))
	})

	It("logs an IPv6 query and reports a missing response", func() {
		name := uniqueName("v6")
		runIn(handle1Init, "-server", "::1", "-name", name)

		Eventually(queries(name), "5s").Should(HaveLen(1))
		line := queries(name)()[0]
		Expect(line.Data["query"]).To(HaveKeyWithValue("family", "ipv6"))
		Expect(line.Data["response"]).To(Equal(map[string]interface{}{"received": false}))
	})

	It("attributes a query with a spoofed source address to the sending container", func() {
		name := uniqueName("spoofed")
		runIn(handle2Init, "-server", serverIP, "-name", name, "-proto", "raw", "-spoof-source", "10.99.99.99")

		Eventually(queries(name), "5s").Should(HaveLen(1))
		line := queries(name)()[0]
		Expect(line.Data["container"]).To(HaveKeyWithValue("handle", "handle-2"))
		Expect(line.Data["query"]).To(HaveKeyWithValue("src_ip", "10.99.99.99"))
	})

	It("attributes processes in sibling cgroups to their container", func() {
		name := uniqueName("healthcheck")
		runIn(healthcheck, "-server", serverIP, "-name", name)

		Eventually(queries(name), "5s").Should(HaveLen(1))
		Expect(queries(name)()[0].Data["container"]).To(And(
			HaveKeyWithValue("handle", "handle-1"),
			HaveKeyWithValue("cgroup", "handle-1-liveness-healthcheck-0"),
		))
	})

	It("logs a name with a dot inside a label in escaped form", func() {
		label := fmt.Sprintf("dotted\\.label%d", GinkgoParallelProcess())
		runIn(handle1Init, "-server", serverIP, "-name", label+".it.example")

		Eventually(queries(label+".it.example"), "5s").Should(HaveLen(1))
	})

	It("captures the whole query when it is larger than the capture length", func() {
		name := uniqueName("padded")
		runIn(handle1Init, "-server", serverIP, "-name", name, "-padding", "3000")

		Eventually(queries(name), "5s").Should(HaveLen(1))
	})

	It("doesn't log queries from processes outside the cgroup tree", func() {
		name := uniqueName("host")
		cmd := exec.Command(clientPath, "-server", serverIP, "-name", name)
		Expect(cmd.Run()).To(Succeed())
		marker := uniqueName("marker")
		runIn(handle1Init, "-server", serverIP, "-name", marker)

		Eventually(queries(marker), "5s").Should(HaveLen(1))
		Expect(queries(name)()).To(BeEmpty())
	})

	It("doesn't log excluded domains", func() {
		runIn(handle1Init, "-server", serverIP, "-name", "x.excluded.it.example")
		marker := uniqueName("marker-excluded")
		runIn(handle1Init, "-server", serverIP, "-name", marker)

		Eventually(queries(marker), "5s").Should(HaveLen(1))
		Expect(queries("x.excluded.it.example")()).To(BeEmpty())
	})

	It("deduplicates repeats and reports the count", func() {
		name := uniqueName("repeat")
		for i := 0; i < 3; i++ {
			runIn(handle1Init, "-server", serverIP, "-name", name, "-id", fmt.Sprint(100+i))
		}

		Eventually(func() []logLine {
			var out []logLine
			for _, l := range readLog() {
				query, _ := l.Data["query"].(map[string]interface{})
				if l.Message == "garden.dns-audit.dns-repeats" && query["name"] == name {
					out = append(out, l)
				}
			}
			return out
		}, "5s").Should(ContainElement(HaveField("Data", HaveKeyWithValue("repeats_suppressed", BeNumerically("==", 2)))))
		Expect(queries(name)()).To(HaveLen(1))
	})

	It("rate limits each container and summarises the dropped queries by suffix", func() {
		for i := 0; i < 15; i++ {
			runIn(handle2Init, "-server", serverIP, "-name", fmt.Sprintf("q%d.%s", i, uniqueName("burst")))
		}

		Eventually(func() []logLine {
			var out []logLine
			for _, l := range readLog() {
				if l.Message == "garden.dns-audit.dns-rate-limited" {
					out = append(out, l)
				}
			}
			return out
		}, "5s").Should(ContainElement(HaveField("Data", And(
			HaveKeyWithValue("dropped", BeNumerically(">", 0)),
			HaveKeyWithValue("container", HaveKeyWithValue("handle", "handle-2")),
			HaveKeyWithValue("top_suffixes", ContainElement(HaveKeyWithValue("suffix", "it.example"))),
		))))
	})

	It("reports metrics", func() {
		Eventually(session, "5s").Should(gbytes.Say(`dns-audit.metrics.*"kernel_events"`))
	})

	It("detaches its programs when it stops", func() {
		attached := func() string {
			out, err := exec.Command(attachedPath, cgroupRoot).CombinedOutput()
			Expect(err).NotTo(HaveOccurred(), string(out))
			return string(out)
		}
		Expect(attached()).To(And(ContainSubstring("dns_egress"), ContainSubstring("dns_ingress")))

		session.Terminate()
		Eventually(session, "10s").Should(gexec.Exit(0))
		Eventually(attached, "5s").Should(BeEmpty())
	})

	It("detaches its programs when it is killed", func() {
		session.Kill()
		Eventually(session, "10s").Should(gexec.Exit())
		Eventually(func() string {
			out, _ := exec.Command(attachedPath, cgroupRoot).CombinedOutput()
			return string(out)
		}, "5s").Should(BeEmpty())
	})

	Context("without response capture", func() {
		BeforeEach(func() {
			cfg["capture_responses"] = false
		})

		It("attaches only the egress program and logs immediately", func() {
			out, err := exec.Command(attachedPath, cgroupRoot).CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(out)).To(ContainSubstring("dns_egress"))
			Expect(string(out)).NotTo(ContainSubstring("dns_ingress"))

			name := uniqueName("noresp")
			runIn(handle1Init, "-server", serverIP, "-name", name)
			Eventually(queries(name), "5s").Should(HaveLen(1))
			Expect(queries(name)()[0].Data).NotTo(HaveKey("response"))
		})
	})

	Context("when Garden is unavailable", func() {
		BeforeEach(func() {
			garden.Stop()
			garden = nil
		})

		It("logs the handle without properties", func() {
			name := uniqueName("nogarden")
			runIn(handle1Init, "-server", serverIP, "-name", name)
			Eventually(queries(name), "5s").Should(HaveLen(1))
			Expect(queries(name)()[0].Data["container"]).To(Equal(map[string]interface{}{"handle": "handle-1", "cgroup": "handle-1/init"}))
		})
	})

	Context("when disabled", func() {
		BeforeEach(func() {
			cfg["enabled"] = false
			waitStart = false
		})

		It("exits without attaching anything", func() {
			Eventually(session, "5s").Should(gexec.Exit(0))
			Expect(session).To(gbytes.Say("dns-audit.disabled"))
			out, err := exec.Command(attachedPath, cgroupRoot).CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(out)).To(BeEmpty())
			Expect(dnsLog).NotTo(BeAnExistingFile())
		})
	})

	Context("when the cgroup root doesn't exist", func() {
		BeforeEach(func() {
			cfg["cgroup_root"] = filepath.Join(cgroupRoot, "missing")
			waitStart = false
		})

		It("fails at start-up", func() {
			Eventually(session, "10s").Should(gexec.Exit(1))
			Expect(session).To(gbytes.Say("attach"))
		})
	})

	It("keeps working after the logged-to file is truncated by log rotation", func() {
		first := uniqueName("before-rotate")
		runIn(handle1Init, "-server", serverIP, "-name", first)
		Eventually(queries(first), "5s").Should(HaveLen(1))

		Expect(os.Truncate(dnsLog, 0)).To(Succeed())
		second := uniqueName("after-rotate")
		runIn(handle1Init, "-server", serverIP, "-name", second)
		Eventually(queries(second), "5s").Should(HaveLen(1))
		contents, err := os.ReadFile(dnsLog)
		Expect(err).NotTo(HaveOccurred())
		Expect(contents[0]).To(Equal(byte('{')))
	})
})
