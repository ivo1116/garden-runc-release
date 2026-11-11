package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"code.cloudfoundry.org/guardian/dnsaudit/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}

var _ = Describe("Load", func() {
	var (
		path   string
		values map[string]interface{}
	)

	BeforeEach(func() {
		path = filepath.Join(GinkgoT().TempDir(), "config.json")
		values = map[string]interface{}{
			"enabled":                           true,
			"cgroup_root":                       "/sys/fs/cgroup/garden",
			"garden_address":                    "/var/vcap/data/garden/garden.sock",
			"output_log_file":                   "/var/vcap/sys/log/dns-audit/dns.log",
			"host_ip":                           "10.0.0.1",
			"host_id":                           "cell-id",
			"properties":                        []string{"network.app_id", "app_name"},
			"dedup_window_seconds":              60,
			"max_logs_per_second_per_container": 10,
			"exclude_domains":                   []string{"cf.internal"},
			"capture_responses":                 true,
		}
	})

	write := func() {
		contents, err := json.Marshal(values)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(path, contents, 0644)).To(Succeed())
	}

	It("loads the config and applies defaults", func() {
		write()
		c, err := config.Load(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(c).To(Equal(config.Config{
			Enabled:                      true,
			CgroupRoot:                   "/sys/fs/cgroup/garden",
			GardenNetwork:                "unix",
			GardenAddress:                "/var/vcap/data/garden/garden.sock",
			OutputLogFile:                "/var/vcap/sys/log/dns-audit/dns.log",
			HostIP:                       "10.0.0.1",
			HostID:                       "cell-id",
			Properties:                   []string{"network.app_id", "app_name"},
			DedupWindowSeconds:           60,
			MaxLogsPerSecondPerContainer: 10,
			MaxLogsPerSecond:             config.DefaultMaxLogsPerSecond,
			ExcludeDomains:               []string{"cf.internal"},
			CaptureResponses:             true,
			ResponseTimeoutMillis:        config.DefaultResponseTimeoutMillis,
			RingBufferSizeKB:             config.DefaultRingBufferSizeKB,
			PropertyCacheTTLSeconds:      config.DefaultPropertyCacheTTLSeconds,
			MetricsIntervalSeconds:       config.DefaultMetricsIntervalSeconds,
		}))
	})

	It("doesn't validate a disabled config", func() {
		values = map[string]interface{}{"enabled": false}
		write()
		_, err := config.Load(path)
		Expect(err).NotTo(HaveOccurred())
	})

	It("fails for a missing or invalid file", func() {
		_, err := config.Load(filepath.Join(GinkgoT().TempDir(), "missing.json"))
		Expect(err).To(MatchError(ContainSubstring("reading config")))

		Expect(os.WriteFile(path, []byte("{"), 0644)).To(Succeed())
		_, err = config.Load(path)
		Expect(err).To(MatchError(ContainSubstring("parsing config")))
	})

	DescribeTable("invalid values",
		func(key string, value interface{}, message string) {
			values[key] = value
			write()
			_, err := config.Load(path)
			Expect(err).To(MatchError("invalid config: " + message))
		},
		Entry("cgroup root", "cgroup_root", "", "cgroup_root must be set"),
		Entry("garden address", "garden_address", "", "garden_address must be set"),
		Entry("output log file", "output_log_file", "", "output_log_file must be set"),
		Entry("dedup window", "dedup_window_seconds", 0, "dedup_window_seconds must be greater than 0"),
		Entry("rate", "max_logs_per_second_per_container", -1, "max_logs_per_second_per_container must be greater than 0"),
		Entry("cell rate", "max_logs_per_second", -1, "max_logs_per_second must be greater than 0"),
		Entry("response timeout", "response_timeout_millis", -1, "response_timeout_millis must not be negative"),
		Entry("ring buffer not a power of two", "ring_buffer_size_kb", 1000, "ring_buffer_size_kb must be a power of two and at least 4"),
		Entry("ring buffer too small", "ring_buffer_size_kb", 2, "ring_buffer_size_kb must be a power of two and at least 4"),
		Entry("empty excluded domain", "exclude_domains", []string{"."}, "exclude_domains must not contain empty entries"),
		Entry("empty property key", "properties", []string{" "}, "properties must not contain empty entries"),
	)
})
