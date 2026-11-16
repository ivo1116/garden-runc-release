package runcontainerd_test

import (
	"errors"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd/runcontainerdfakes"
	"code.cloudfoundry.org/lager/v3/lagertest"
	"github.com/containerd/cgroups/v3/cgroup2/stats"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TaskStatser", func() {
	var (
		metricsGetter *runcontainerdfakes.FakeTaskMetricsGetter
		statser       *runcontainerd.TaskStatser
		logger        *lagertest.TestLogger

		containerMetrics gardener.StatsContainerMetrics
		statsErr         error
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		metricsGetter = new(runcontainerdfakes.FakeTaskMetricsGetter)
		metricsGetter.MetricsReturns(&stats.Metrics{
			CPU: &stats.CPUStat{UsageUsec: 3, UserUsec: 2, SystemUsec: 1},
			Memory: &stats.MemoryStat{
				Anon:         100,
				File:         50,
				InactiveFile: 20,
				ActiveFile:   30,
				ActiveAnon:   60,
				InactiveAnon: 40,
				Unevictable:  5,
				Pgfault:      7,
				Pgmajfault:   8,
			},
			Pids: &stats.PidsStat{Current: 4, Limit: 1024},
		}, nil)
		metricsGetter.CreatedAtReturns(time.Now().Add(-time.Hour), nil)
		statser = runcontainerd.NewTaskStatser(metricsGetter)
	})

	JustBeforeEach(func() {
		containerMetrics, statsErr = statser.Stats(logger, "some-handle")
	})

	It("gets the metrics of the container's task", func() {
		Expect(statsErr).NotTo(HaveOccurred())
		Expect(metricsGetter.MetricsCallCount()).To(Equal(1))
		_, id := metricsGetter.MetricsArgsForCall(0)
		Expect(id).To(Equal("some-handle"))
		_, id = metricsGetter.CreatedAtArgsForCall(0)
		Expect(id).To(Equal("some-handle"))
	})

	It("converts CPU usage to nanoseconds", func() {
		Expect(containerMetrics.CPU).To(Equal(garden.ContainerCPUStat{Usage: 3000, User: 2000, System: 1000}))
	})

	It("converts the memory stats", func() {
		Expect(containerMetrics.Memory).To(Equal(garden.ContainerMemoryStat{
			Anon:                  100,
			File:                  50,
			InactiveFile:          20,
			ActiveFile:            30,
			ActiveAnon:            60,
			InactiveAnon:          40,
			Unevictable:           5,
			Pgfault:               7,
			Pgmajfault:            8,
			TotalUsageTowardLimit: 130,
		}))
	})

	It("converts the pid stats", func() {
		Expect(containerMetrics.Pid).To(Equal(garden.ContainerPidStat{Current: 4, Max: 1024}))
	})

	It("computes the age from the container creation time", func() {
		Expect(containerMetrics.Age).To(BeNumerically("~", time.Hour, time.Minute))
	})

	Context("when inactive file memory is larger than the usage", func() {
		BeforeEach(func() {
			metricsGetter.MetricsReturns(&stats.Metrics{Memory: &stats.MemoryStat{Anon: 1, File: 1, InactiveFile: 5}}, nil)
		})

		It("reports zero usage", func() {
			Expect(containerMetrics.Memory.TotalUsageTowardLimit).To(BeZero())
		})
	})

	Context("when the metrics have no sections", func() {
		BeforeEach(func() {
			metricsGetter.MetricsReturns(&stats.Metrics{}, nil)
		})

		It("returns zero values", func() {
			Expect(statsErr).NotTo(HaveOccurred())
			Expect(containerMetrics.CPU).To(BeZero())
			Expect(containerMetrics.Memory).To(BeZero())
			Expect(containerMetrics.Pid).To(BeZero())
		})
	})

	Context("when getting the metrics fails", func() {
		BeforeEach(func() {
			metricsGetter.MetricsReturns(nil, errors.New("metrics-err"))
		})

		It("returns the error", func() {
			Expect(statsErr).To(MatchError("metrics-err"))
		})
	})

	Context("when getting the creation time fails", func() {
		BeforeEach(func() {
			metricsGetter.CreatedAtReturns(time.Time{}, errors.New("created-err"))
		})

		It("returns the error", func() {
			Expect(statsErr).To(MatchError("created-err"))
		})
	})
})
