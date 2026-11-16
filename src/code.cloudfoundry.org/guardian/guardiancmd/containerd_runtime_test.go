package guardiancmd_test

import (
	"os"
	"path/filepath"

	"code.cloudfoundry.org/guardian/guardiancmd"
	"github.com/jessevdk/go-flags"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ValidateContainerdRuntime", func() {
	var (
		cmd     *guardiancmd.CommonCommand
		tmpDir  string
		shimBin string
	)

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
		shimBin = filepath.Join(tmpDir, "containerd-shim-test-v2")
		Expect(os.WriteFile(shimBin, []byte("#!/bin/sh\n"), 0755)).To(Succeed())

		cmd = &guardiancmd.CommonCommand{}
		cmd.Containerd.Socket = "/run/containerd.sock"
		cmd.Containerd.Runtime = shimBin
		cmd.Containerd.RuntimeTarPath = "/.fc/bin/tar"
	})

	It("succeeds for an executable shim path", func() {
		Expect(cmd.ValidateContainerdRuntime()).To(Succeed())
	})

	It("succeeds for a runtime name", func() {
		cmd.Containerd.Runtime = "io.containerd.test.v2"
		Expect(cmd.ValidateContainerdRuntime()).To(Succeed())
	})

	It("succeeds when no runtime is set, whatever the other flags are", func() {
		cmd.Containerd.Runtime = ""
		cmd.Containerd.Socket = ""
		cmd.CPUThrottling.Enabled = true
		Expect(cmd.ValidateContainerdRuntime()).To(Succeed())
	})

	It("fails when containerd mode is off", func() {
		cmd.Containerd.Socket = ""
		Expect(cmd.ValidateContainerdRuntime()).To(MatchError(ContainSubstring("requires containerd mode")))
	})

	It("fails when CPU throttling is enabled", func() {
		cmd.CPUThrottling.Enabled = true
		Expect(cmd.ValidateContainerdRuntime()).To(MatchError(ContainSubstring("cannot be combined with --enable-cpu-throttling")))
	})

	It("fails when the tar path is empty", func() {
		cmd.Containerd.RuntimeTarPath = ""
		Expect(cmd.ValidateContainerdRuntime()).To(MatchError(ContainSubstring("--containerd-runtime-tar-path")))
	})

	It("fails when the shim path does not exist", func() {
		cmd.Containerd.Runtime = filepath.Join(tmpDir, "missing")
		Expect(cmd.ValidateContainerdRuntime()).To(MatchError(ContainSubstring("no such file or directory")))
	})

	It("fails when the shim path is not executable", func() {
		Expect(os.Chmod(shimBin, 0644)).To(Succeed())
		Expect(cmd.ValidateContainerdRuntime()).To(MatchError(ContainSubstring("is not an executable file")))
	})

	It("fails when the shim path is a directory", func() {
		cmd.Containerd.Runtime = tmpDir
		Expect(cmd.ValidateContainerdRuntime()).To(MatchError(ContainSubstring("is not an executable file")))
	})

	It("defaults the tar path when parsing flags", func() {
		parsed := &guardiancmd.CommonCommand{}
		_, err := flags.NewParser(parsed, flags.Default).ParseArgs([]string{"--containerd-runtime", "io.containerd.test.v2"})
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed.Containerd.Runtime).To(Equal("io.containerd.test.v2"))
		Expect(parsed.Containerd.RuntimeTarPath).To(Equal("/.fc/bin/tar"))
	})
})
