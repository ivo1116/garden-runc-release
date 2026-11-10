//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/dnsaudit/audit"
	"code.cloudfoundry.org/guardian/dnsaudit/capture"
	"code.cloudfoundry.org/guardian/dnsaudit/config"
	"code.cloudfoundry.org/guardian/dnsaudit/identity"
	"code.cloudfoundry.org/lager/v3"
)

const (
	tickInterval  = 250 * time.Millisecond
	gardenTimeout = 5 * time.Second
	maxDedupBytes = 32 * 1024 * 1024
	maxPending    = 20000
	maxSuffixes   = 200
	topSuffixes   = 10
	burstFactor   = 5
	recordQueue   = 4096

	// After a read error other than an invalid record, wait this long before
	// reading again, and log read errors at most once per readErrorLogInterval.
	readErrorBackoff     = 100 * time.Millisecond
	readErrorLogInterval = time.Minute

	// On shutdown, records written before the programs were detached are read
	// for this long. The reader polls the ring buffer every 50 ms.
	shutdownDrain = 200 * time.Millisecond
)

func main() {
	configPath := flag.String("config", "", "path to the JSON config file")
	flag.Parse()

	logger := lager.NewLogger("dns-audit")
	logger.RegisterSink(lager.NewPrettySink(os.Stdout, lager.INFO))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("load-config", err)
	}
	if !cfg.Enabled {
		logger.Info("disabled")
		return
	}

	if err := run(cfg, logger); err != nil {
		logger.Error("exited", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, logger lager.Logger) error {
	output, err := os.OpenFile(cfg.OutputLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)
	if err != nil {
		return fmt.Errorf("open output log file: %w", err)
	}
	defer output.Close()
	dnsLogger := lager.NewLogger("garden.dns-audit")
	dnsLogger.RegisterSink(lager.NewPrettySink(output, lager.INFO))

	cgroups := identity.NewCgroupIndex(cfg.CgroupRoot, time.Now)
	cgroups.Scan()
	source := identity.NewGardenSource(cfg.GardenNetwork, cfg.GardenAddress, gardenTimeout, logger.Session("garden"))
	resolver := identity.NewResolver(cgroups, source, cfg.Properties,
		time.Duration(cfg.PropertyCacheTTLSeconds)*time.Second, time.Now, logger.Session("resolver"))
	resolver.Refresh()
	stopResolver := make(chan struct{})
	defer close(stopResolver)
	go resolver.Run(stopResolver)

	processor := audit.NewProcessor(audit.Options{
		DedupWindow:       time.Duration(cfg.DedupWindowSeconds) * time.Second,
		RatePerSecond:     cfg.MaxLogsPerSecondPerContainer,
		Burst:             burstFactor * cfg.MaxLogsPerSecondPerContainer,
		CellRatePerSecond: cfg.MaxLogsPerSecond,
		CellBurst:         burstFactor * cfg.MaxLogsPerSecond,
		ExcludeDomains:    cfg.ExcludeDomains,
		CaptureResponses:  cfg.CaptureResponses,
		ResponseTimeout:   time.Duration(cfg.ResponseTimeoutMillis) * time.Millisecond,
		MaxDedupBytes:     maxDedupBytes,
		MaxPending:        maxPending,
		MaxSuffixes:       maxSuffixes,
		TopSuffixes:       topSuffixes,
		Host:              audit.Host{IP: cfg.HostIP, ID: cfg.HostID},
	}, resolver, dnsLogger, time.Now)

	c, err := capture.Open(cfg.CgroupRoot, cfg.RingBufferSizeKB*1024, cfg.CaptureResponses)
	if err != nil {
		return err
	}
	defer c.Close()

	logger.Info("started", lager.Data{
		"cgroup_root":       cfg.CgroupRoot,
		"capture_responses": cfg.CaptureResponses,
		"output_log_file":   cfg.OutputLogFile,
	})

	clock := capture.NewClock(capture.Monotonic, time.Now)
	records := make(chan capture.Record, recordQueue)
	closed := make(chan error, 1)
	var readErrors atomic.Uint64
	go func() {
		var lastLogged time.Time
		for {
			record, ok, err := c.Read()
			switch {
			case errors.Is(err, os.ErrClosed):
				closed <- err
				return
			case err != nil:
				count := readErrors.Add(1)
				if time.Since(lastLogged) >= readErrorLogInterval {
					lastLogged = time.Now()
					logger.Error("read-record", err, lager.Data{"read_errors": count})
				}
				if !errors.Is(err, capture.ErrInvalidRecord) {
					time.Sleep(readErrorBackoff)
				}
			case ok:
				records <- record
			}
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	metricsTicker := time.NewTicker(time.Duration(cfg.MetricsIntervalSeconds) * time.Second)
	defer metricsTicker.Stop()

	report := func() {
		reportMetrics(logger, processor, resolver, c, readErrors.Load())
	}

	for {
		select {
		case record := <-records:
			processor.Handle(record.Event(clock))
		case <-ticker.C:
			processor.Tick()
		case <-metricsTicker.C:
			clock.Resync()
			report()
		case err := <-closed:
			return fmt.Errorf("ring buffer closed: %w", err)
		case sig := <-signals:
			logger.Info("stopping", lager.Data{"signal": sig.String()})
			if err := c.Detach(); err != nil {
				logger.Error("detach", err)
			}
			drained := time.After(shutdownDrain)
			for draining := true; draining; {
				select {
				case record := <-records:
					processor.Handle(record.Event(clock))
				case <-drained:
					draining = false
				}
			}
			if err := c.Close(); err != nil {
				logger.Error("close", err)
			}
			for draining := true; draining; {
				select {
				case record := <-records:
					processor.Handle(record.Event(clock))
				default:
					draining = false
				}
			}
			processor.Flush()
			report()
			logger.Info("stopped")
			return nil
		}
	}
}

func reportMetrics(logger lager.Logger, processor *audit.Processor, resolver *identity.Resolver, c *capture.Capture, readErrors uint64) {
	values := processor.Counters.Values()
	values["garden_errors"] = resolver.GardenErrors.Load()
	values["unknown_cgroups"] = resolver.UnknownCgroups.Load()
	values["missing_properties"] = resolver.MissingProperties.Load()
	values["read_errors"] = readErrors
	values["pending_responses"] = uint64(processor.PendingLen())
	if stats, err := c.Stats(); err == nil {
		values["kernel_events"] = stats.Events
		values["ringbuf_full"] = stats.RingbufFull
		values["kernel_load_errors"] = stats.LoadErrors
	}

	data := lager.Data{}
	for _, name := range audit.SortedNames(values) {
		data[name] = values[name]
	}
	logger.Info("metrics", data)
}
