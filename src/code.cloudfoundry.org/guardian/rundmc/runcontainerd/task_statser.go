package runcontainerd

import (
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/lager/v3"
	"github.com/containerd/cgroups/v3/cgroup2/stats"
)

//counterfeiter:generate . TaskMetricsGetter
type TaskMetricsGetter interface {
	Metrics(log lager.Logger, containerID string) (*stats.Metrics, error)
	CreatedAt(log lager.Logger, containerID string) (time.Time, error)
}

type TaskStatser struct {
	metricsGetter TaskMetricsGetter
}

func NewTaskStatser(metricsGetter TaskMetricsGetter) *TaskStatser {
	return &TaskStatser{metricsGetter: metricsGetter}
}

func (s *TaskStatser) Stats(log lager.Logger, id string) (gardener.StatsContainerMetrics, error) {
	metrics, err := s.metricsGetter.Metrics(log, id)
	if err != nil {
		return gardener.StatsContainerMetrics{}, err
	}

	createdAt, err := s.metricsGetter.CreatedAt(log, id)
	if err != nil {
		return gardener.StatsContainerMetrics{}, err
	}

	containerMetrics := gardener.StatsContainerMetrics{Age: time.Since(createdAt)}

	if cpu := metrics.GetCPU(); cpu != nil {
		containerMetrics.CPU = garden.ContainerCPUStat{
			Usage:  cpu.UsageUsec * 1000,
			User:   cpu.UserUsec * 1000,
			System: cpu.SystemUsec * 1000,
		}
	}

	if memory := metrics.GetMemory(); memory != nil {
		containerMetrics.Memory = garden.ContainerMemoryStat{
			ActiveAnon:   memory.ActiveAnon,
			ActiveFile:   memory.ActiveFile,
			InactiveAnon: memory.InactiveAnon,
			InactiveFile: memory.InactiveFile,
			Unevictable:  memory.Unevictable,
			Pgfault:      memory.Pgfault,
			Pgmajfault:   memory.Pgmajfault,
			Anon:         memory.Anon,
			File:         memory.File,
		}
		containerMetrics.Memory.TotalUsageTowardLimit = totalUsageTowardLimit(memory)
	}

	if pids := metrics.GetPids(); pids != nil {
		containerMetrics.Pid = garden.ContainerPidStat{
			Current: pids.Current,
			Max:     pids.Limit,
		}
	}

	return containerMetrics, nil
}

func totalUsageTowardLimit(memory *stats.MemoryStat) uint64 {
	usage := memory.File + memory.Anon
	if memory.InactiveFile > usage {
		return 0
	}
	return usage - memory.InactiveFile
}
