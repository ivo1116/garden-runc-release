package runcontainerd_test

import (
	"io"
	"os"
	"path/filepath"

	"code.cloudfoundry.org/guardian/rundmc/goci"
	"code.cloudfoundry.org/guardian/rundmc/runcontainerd"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var _ = Describe("CgroupManager", func() {
	var (
		cgroupManager runcontainerd.CgroupManager
		runcRoot      string
	)

	BeforeEach(func() {
		runcRoot = tempDir("", "runc-root")
		cgroupManager = runcontainerd.NewCgroupManager(runcRoot, "garden")
	})

	AfterEach(func() {
		Expect(os.RemoveAll(runcRoot)).To(Succeed())
	})

	Describe("SetUseMemoryHierarchy", func() {
		var (
			containerHandle  string
			useHierarchyPath string
			stateFilePath    string
			stateFileContent []byte
			setErr           error
			cgroupDir        string
		)

		BeforeEach(func() {
			containerHandle = "potato"

			cgroupDir = tempDir("", "memory-cgroup")

			useHierarchyPath = filepath.Join(cgroupDir, "memory.use_hierarchy")
			writeFile(useHierarchyPath, []byte("0"), os.ModePerm)

			stateFilePath = filepath.Join(runcRoot, "garden", containerHandle, "state.json")
			Expect(os.MkdirAll(filepath.Dir(stateFilePath), os.ModePerm)).To(Succeed())

			stateFileContent = marshal(map[string]interface{}{
				"cgroup_paths": map[string]interface{}{
					"memory": cgroupDir,
				},
			})
		})

		JustBeforeEach(func() {
			writeFile(stateFilePath, stateFileContent, os.ModePerm)
			setErr = cgroupManager.SetUseMemoryHierarchy(containerHandle)
		})

		AfterEach(func() {
			Expect(os.RemoveAll(cgroupDir)).To(Succeed())
		})

		It("sets memory.use_hierarchy to 1 for the specified container", func() {
			Expect(setErr).NotTo(HaveOccurred())
			Expect(os.ReadFile(useHierarchyPath)).To(Equal([]byte("1")))
		})

		Context("when the state dir for the container doesn't exist", func() {
			BeforeEach(func() {
				containerHandle = "foo"
			})

			It("returns an error", func() {
				Expect(setErr).To(HaveOccurred())
			})
		})

		Context("when the container state file is malformed", func() {
			BeforeEach(func() {
				stateFileContent = nil
			})

			It("returns an error", func() {
				Expect(setErr).To(Equal(io.EOF))
			})
		})
	})
})

var _ = Describe("RuntimeOwnedCgroupManager", func() {
	var cgroupManager runcontainerd.CgroupManager

	BeforeEach(func() {
		cgroupManager = runcontainerd.NewRuntimeOwnedCgroupManager()
	})

	It("leaves the bundle and the cgroups alone", func() {
		bundle := goci.Bundle().WithCGroupPath("/garden/some-handle").WithMemoryLimit(specs.LinuxMemory{Limit: int64ptr(1024)})
		bundle.Spec.Annotations = map[string]string{"container-type": "garden-init"}
		original := bundle.Spec

		Expect(cgroupManager.SetUnifiedResources(bundle)).To(Succeed())
		cgroupManager.AddCgroupBindMount(&bundle)
		Expect(bundle.Spec).To(Equal(original))
		Expect(cgroupManager.SetUseMemoryHierarchy("some-handle")).To(Succeed())
	})
})

func int64ptr(i int64) *int64 {
	return &i
}
