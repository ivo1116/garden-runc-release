package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	DefaultRingBufferSizeKB        = 4096
	DefaultPropertyCacheTTLSeconds = 60
	DefaultMetricsIntervalSeconds  = 30
	DefaultResponseTimeoutMillis   = 2000
	DefaultMaxLogsPerSecond        = 100
)

type Config struct {
	Enabled                      bool     `json:"enabled"`
	CgroupRoot                   string   `json:"cgroup_root"`
	GardenNetwork                string   `json:"garden_network"`
	GardenAddress                string   `json:"garden_address"`
	OutputLogFile                string   `json:"output_log_file"`
	HostIP                       string   `json:"host_ip"`
	HostID                       string   `json:"host_id"`
	Properties                   []string `json:"properties"`
	DedupWindowSeconds           int      `json:"dedup_window_seconds"`
	MaxLogsPerSecondPerContainer int      `json:"max_logs_per_second_per_container"`
	MaxLogsPerSecond             int      `json:"max_logs_per_second"`
	ExcludeDomains               []string `json:"exclude_domains"`
	CaptureResponses             bool     `json:"capture_responses"`
	ResponseTimeoutMillis        int      `json:"response_timeout_millis"`
	RingBufferSizeKB             int      `json:"ring_buffer_size_kb"`
	PropertyCacheTTLSeconds      int      `json:"property_cache_ttl_seconds"`
	MetricsIntervalSeconds       int      `json:"metrics_interval_seconds"`
}

func Load(path string) (Config, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}

	var c Config
	if err := json.Unmarshal(contents, &c); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	c.applyDefaults()

	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("invalid config: %w", err)
	}
	return c, nil
}

func (c *Config) applyDefaults() {
	if c.RingBufferSizeKB == 0 {
		c.RingBufferSizeKB = DefaultRingBufferSizeKB
	}
	if c.PropertyCacheTTLSeconds == 0 {
		c.PropertyCacheTTLSeconds = DefaultPropertyCacheTTLSeconds
	}
	if c.MetricsIntervalSeconds == 0 {
		c.MetricsIntervalSeconds = DefaultMetricsIntervalSeconds
	}
	if c.ResponseTimeoutMillis == 0 {
		c.ResponseTimeoutMillis = DefaultResponseTimeoutMillis
	}
	if c.MaxLogsPerSecond == 0 {
		c.MaxLogsPerSecond = DefaultMaxLogsPerSecond
	}
	if c.GardenNetwork == "" {
		c.GardenNetwork = "unix"
	}
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch {
	case c.CgroupRoot == "":
		return errors.New("cgroup_root must be set")
	case c.GardenAddress == "":
		return errors.New("garden_address must be set")
	case c.OutputLogFile == "":
		return errors.New("output_log_file must be set")
	case c.DedupWindowSeconds <= 0:
		return errors.New("dedup_window_seconds must be greater than 0")
	case c.MaxLogsPerSecondPerContainer <= 0:
		return errors.New("max_logs_per_second_per_container must be greater than 0")
	case c.MaxLogsPerSecond <= 0:
		return errors.New("max_logs_per_second must be greater than 0")
	case c.ResponseTimeoutMillis < 0:
		return errors.New("response_timeout_millis must not be negative")
	case c.PropertyCacheTTLSeconds < 0:
		return errors.New("property_cache_ttl_seconds must not be negative")
	case c.MetricsIntervalSeconds < 0:
		return errors.New("metrics_interval_seconds must not be negative")
	}

	size := c.RingBufferSizeKB
	if size < 4 || size&(size-1) != 0 {
		return errors.New("ring_buffer_size_kb must be a power of two and at least 4")
	}

	for _, domain := range c.ExcludeDomains {
		if strings.Trim(strings.TrimSpace(domain), ".") == "" {
			return errors.New("exclude_domains must not contain empty entries")
		}
	}
	for _, key := range c.Properties {
		if strings.TrimSpace(key) == "" {
			return errors.New("properties must not contain empty entries")
		}
	}
	return nil
}
