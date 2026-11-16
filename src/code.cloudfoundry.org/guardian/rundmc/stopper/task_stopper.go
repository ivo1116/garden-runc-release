package stopper

import (
	"fmt"
	"syscall"

	"code.cloudfoundry.org/lager/v3"
)

//counterfeiter:generate . TaskKiller

type TaskKiller interface {
	KillAll(log lager.Logger, handle string, signal syscall.Signal) error
	ProcessCount(log lager.Logger, handle string) (int, error)
}

// TaskStopper signals every process of a container through the containerd
// runtime. Unlike CgroupStopper it cannot spare the init process.
type TaskStopper struct {
	killer  TaskKiller
	retrier Retrier
}

func NewTaskStopper(killer TaskKiller, retrier Retrier) *TaskStopper {
	return &TaskStopper{killer: killer, retrier: retrier}
}

func (s *TaskStopper) StopAll(log lager.Logger, handle string, _ []int, kill bool) error {
	log = log.Session("task-stop-all", lager.Data{"handle": handle})

	log.Debug("start")
	defer log.Debug("finished")

	if !kill {
		if err := s.killer.KillAll(log, handle, syscall.SIGTERM); err != nil {
			log.Debug("failed-to-terminate-processes", lager.Data{"error": err})
		}

		err := s.retrier.Run(func() error {
			count, err := s.killer.ProcessCount(log, handle)
			if err != nil {
				return err
			}
			if count > 1 {
				return fmt.Errorf("%d processes still running after SIGTERM", count)
			}
			return nil
		})
		if err != nil {
			log.Debug("processes-still-running", lager.Data{"error": err})
		}
	}

	return s.killer.KillAll(log, handle, syscall.SIGKILL)
}
