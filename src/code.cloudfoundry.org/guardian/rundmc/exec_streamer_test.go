package rundmc_test

import (
	"errors"
	"io"
	"strings"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/garden/gardenfakes"
	"code.cloudfoundry.org/guardian/rundmc"
	fakes "code.cloudfoundry.org/guardian/rundmc/rundmcfakes"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ExecStreamer", func() {
	var (
		execer   *fakes.FakeProcessExecer
		process  *gardenfakes.FakeProcess
		streamer *rundmc.ExecStreamer
		logger   lager.Logger
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		execer = new(fakes.FakeProcessExecer)
		process = new(gardenfakes.FakeProcess)
		execer.ExecReturns(process, nil)
		streamer = rundmc.NewExecStreamer(execer, "/.fc/bin/tar")
	})

	Describe("StreamIn", func() {
		var (
			spec        garden.StreamInSpec
			streamInErr error
		)

		BeforeEach(func() {
			spec = garden.StreamInSpec{
				Path:      "/home/vcap/app",
				User:      "vcap",
				TarStream: strings.NewReader("tar-data"),
			}
		})

		JustBeforeEach(func() {
			streamInErr = streamer.StreamIn(logger, "some-handle", spec)
		})

		It("extracts the stream with tar in the destination directory as the user", func() {
			Expect(streamInErr).NotTo(HaveOccurred())
			Expect(execer.ExecCallCount()).To(Equal(1))
			_, handle, processSpec, processIO := execer.ExecArgsForCall(0)
			Expect(handle).To(Equal("some-handle"))
			Expect(processSpec.Path).To(Equal("/.fc/bin/tar"))
			Expect(processSpec.Args).To(Equal([]string{"-x", "-o", "-f", "-", "-C", "/home/vcap/app"}))
			Expect(processSpec.Dir).To(Equal("/home/vcap/app"))
			Expect(processSpec.User).To(Equal("vcap"))
			Expect(processSpec.Image).To(BeZero())
			Expect(processIO.Stdin).To(Equal(spec.TarStream))
			Expect(process.WaitCallCount()).To(Equal(1))
		})

		Context("when the destination is relative", func() {
			BeforeEach(func() {
				spec.Path = "."
			})

			It("extracts in the working directory", func() {
				_, _, processSpec, _ := execer.ExecArgsForCall(0)
				Expect(processSpec.Args).To(Equal([]string{"-x", "-o", "-f", "-"}))
				Expect(processSpec.Dir).To(Equal("."))
			})
		})

		Context("when no user is given", func() {
			BeforeEach(func() {
				spec.User = ""
			})

			It("streams as root", func() {
				_, _, processSpec, _ := execer.ExecArgsForCall(0)
				Expect(processSpec.User).To(Equal("root"))
			})
		})

		Context("when tar fails", func() {
			BeforeEach(func() {
				execer.ExecStub = func(_ lager.Logger, _ string, _ garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
					_, err := pio.Stderr.Write([]byte("no space left"))
					Expect(err).NotTo(HaveOccurred())
					return process, nil
				}
				process.WaitReturns(2, nil)
			})

			It("returns the exit status and stderr", func() {
				Expect(streamInErr).To(MatchError(ContainSubstring("tar exited with status 2: no space left")))
			})
		})

		Context("when waiting fails", func() {
			BeforeEach(func() {
				process.WaitReturns(0, errors.New("wait-failed"))
			})

			It("returns the error", func() {
				Expect(streamInErr).To(MatchError("wait-failed"))
			})
		})

		Context("when exec fails", func() {
			BeforeEach(func() {
				execer.ExecReturns(nil, errors.New("exec-failed"))
			})

			It("returns the error", func() {
				Expect(streamInErr).To(MatchError("exec-failed"))
			})
		})
	})

	Describe("StreamOut", func() {
		var (
			spec     garden.StreamOutSpec
			exitCode int
			stderr   string
		)

		BeforeEach(func() {
			spec = garden.StreamOutSpec{Path: "/tmp/result.json", User: "vcap"}
			exitCode = 0
			stderr = ""
			execer.ExecStub = func(_ lager.Logger, _ string, _ garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					_, err := pio.Stdout.Write([]byte("tar-data"))
					Expect(err).NotTo(HaveOccurred())
					_, err = pio.Stderr.Write([]byte(stderr))
					Expect(err).NotTo(HaveOccurred())
				}()
				process.WaitStub = func() (int, error) {
					<-done
					return exitCode, nil
				}
				return process, nil
			}
		})

		It("archives the file with tar from its parent directory as the user", func() {
			stream, err := streamer.StreamOut(logger, "some-handle", spec)
			Expect(err).NotTo(HaveOccurred())
			Expect(io.ReadAll(stream)).To(Equal([]byte("tar-data")))

			_, handle, processSpec, _ := execer.ExecArgsForCall(0)
			Expect(handle).To(Equal("some-handle"))
			Expect(processSpec.Path).To(Equal("/.fc/bin/tar"))
			Expect(processSpec.Args).To(Equal([]string{"-c", "-f", "-", "-C", "/tmp", "result.json"}))
			Expect(processSpec.Dir).To(Equal("/tmp"))
			Expect(processSpec.User).To(Equal("vcap"))
		})

		Context("when the path ends with a slash", func() {
			BeforeEach(func() {
				spec.Path = "/tmp/results/"
			})

			It("archives the content of the directory", func() {
				stream, err := streamer.StreamOut(logger, "some-handle", spec)
				Expect(err).NotTo(HaveOccurred())
				Expect(io.ReadAll(stream)).To(Equal([]byte("tar-data")))

				_, _, processSpec, _ := execer.ExecArgsForCall(0)
				Expect(processSpec.Args).To(Equal([]string{"-c", "-f", "-", "-C", "/tmp/results/", "."}))
				Expect(processSpec.Dir).To(Equal("/tmp/results/"))
			})
		})

		Context("when no user is given", func() {
			BeforeEach(func() {
				spec.User = ""
			})

			It("streams as root", func() {
				stream, err := streamer.StreamOut(logger, "some-handle", spec)
				Expect(err).NotTo(HaveOccurred())
				Expect(io.ReadAll(stream)).To(Equal([]byte("tar-data")))

				_, _, processSpec, _ := execer.ExecArgsForCall(0)
				Expect(processSpec.User).To(Equal("root"))
			})
		})

		Context("when tar fails", func() {
			BeforeEach(func() {
				exitCode = 2
				stderr = "No such file or directory"
			})

			It("fails the stream with the exit status and stderr", func() {
				stream, err := streamer.StreamOut(logger, "some-handle", spec)
				Expect(err).NotTo(HaveOccurred())
				_, err = io.ReadAll(stream)
				Expect(err).To(MatchError(ContainSubstring("tar exited with status 2: No such file or directory")))
			})
		})

		Context("when exec fails", func() {
			BeforeEach(func() {
				execer.ExecStub = nil
				execer.ExecReturns(nil, errors.New("exec-failed"))
			})

			It("returns the error", func() {
				_, err := streamer.StreamOut(logger, "some-handle", spec)
				Expect(err).To(MatchError("exec-failed"))
			})
		})
	})
})
