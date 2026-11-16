package stopper_test

import (
	"errors"
	"syscall"

	"code.cloudfoundry.org/guardian/rundmc/stopper"
	fakes "code.cloudfoundry.org/guardian/rundmc/stopper/stopperfakes"
	"code.cloudfoundry.org/lager/v3/lagertest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TaskStopper", func() {
	var (
		fakeKiller  *fakes.FakeTaskKiller
		fakeRetrier *fakes.FakeRetrier
		subject     *stopper.TaskStopper
		logger      *lagertest.TestLogger
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		fakeKiller = new(fakes.FakeTaskKiller)
		fakeRetrier = new(fakes.FakeRetrier)
		fakeRetrier.RunStub = func(fn func() error) error {
			return fn()
		}
		subject = stopper.NewTaskStopper(fakeKiller, fakeRetrier)
	})

	signals := func() []syscall.Signal {
		var sent []syscall.Signal
		for i := 0; i < fakeKiller.KillAllCallCount(); i++ {
			_, handle, signal := fakeKiller.KillAllArgsForCall(i)
			Expect(handle).To(Equal("some-handle"))
			sent = append(sent, signal)
		}
		return sent
	}

	Context("when the kill flag is false", func() {
		It("sends TERM, waits for the processes to exit and then sends KILL to all processes", func() {
			fakeKiller.ProcessCountReturns(1, nil)
			Expect(subject.StopAll(logger, "some-handle", []int{1}, false)).To(Succeed())
			Expect(signals()).To(Equal([]syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}))
			Expect(fakeRetrier.RunCallCount()).To(Equal(1))
		})

		It("reports processes that are still running to the retrier", func() {
			fakeKiller.ProcessCountReturns(3, nil)
			var retryErr error
			fakeRetrier.RunStub = func(fn func() error) error {
				retryErr = fn()
				return retryErr
			}
			Expect(subject.StopAll(logger, "some-handle", nil, false)).To(Succeed())
			Expect(retryErr).To(MatchError(ContainSubstring("3 processes still running")))
			Expect(signals()).To(Equal([]syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}))
		})

		It("still sends KILL when TERM fails", func() {
			fakeKiller.KillAllReturnsOnCall(0, errors.New("term-failed"))
			Expect(subject.StopAll(logger, "some-handle", nil, false)).To(Succeed())
			Expect(signals()).To(Equal([]syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}))
		})
	})

	Context("when the kill flag is true", func() {
		It("only sends KILL to all processes", func() {
			Expect(subject.StopAll(logger, "some-handle", nil, true)).To(Succeed())
			Expect(signals()).To(Equal([]syscall.Signal{syscall.SIGKILL}))
			Expect(fakeRetrier.RunCallCount()).To(BeZero())
		})
	})

	It("returns an error when KILL fails", func() {
		fakeKiller.KillAllReturns(errors.New("kill-failed"))
		Expect(subject.StopAll(logger, "some-handle", nil, true)).To(MatchError("kill-failed"))
	})
})
