package bpf_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"code.cloudfoundry.org/guardian/dnsaudit/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestBPF(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BPF Suite")
}

// Helpers the programs may call. None of them is restricted to GPL-licensed
// programs (gpl_only is false in the kernel), which is what allows the
// Apache-2.0 licence string.
var allowedHelpers = map[asm.BuiltinFunc]bool{
	asm.FnSkbLoadBytes:   true,
	asm.FnSkbCgroupId:    true,
	asm.FnKtimeGetNs:     true,
	asm.FnMapLookupElem:  true,
	asm.FnRingbufReserve: true,
	asm.FnRingbufSubmit:  true,
	asm.FnRingbufDiscard: true,
	asm.FnRingbufQuery:   true,
}

// The programs are loaded into the kernel and exercised by the integration
// tests; these tests check what can be checked without a kernel.
var _ = Describe("Spec", func() {
	spec := bpf.Spec(1 << 20)

	It("defines the ring buffer and the per-CPU counters", func() {
		Expect(spec.Maps).To(HaveLen(2))
		Expect(spec.Maps[bpf.EventsMap].Type).To(Equal(ebpf.RingBuf))
		Expect(spec.Maps[bpf.EventsMap].MaxEntries).To(Equal(uint32(1 << 20)))
		Expect(spec.Maps[bpf.StatsMap].Type).To(Equal(ebpf.PerCPUArray))
		Expect(spec.Maps[bpf.StatsMap].MaxEntries).To(Equal(uint32(bpf.NumberOfStats)))
	})

	DescribeTable("programs",
		func(name string, attachType ebpf.AttachType) {
			p := spec.Programs[name]
			Expect(p).NotTo(BeNil())
			Expect(p.Name).To(Equal(name))
			Expect(p.Type).To(Equal(ebpf.CGroupSKB))
			Expect(p.AttachType).To(Equal(attachType))
			Expect(p.License).To(Equal("Apache-2.0"))

			symbols := map[string]bool{}
			for _, ins := range p.Instructions {
				if s := ins.Symbol(); s != "" {
					Expect(symbols).NotTo(HaveKey(s), "duplicate label %s", s)
					symbols[s] = true
				}
			}

			for _, ins := range p.Instructions {
				ref := ins.Reference()
				switch {
				case ins.IsLoadFromMap():
					Expect(spec.Maps).To(HaveKey(ref), "map reference %q", ref)
				case ref != "":
					Expect(symbols).To(HaveKey(ref), "jump to undefined label %q", ref)
				}
				if ins.IsBuiltinCall() {
					Expect(allowedHelpers).To(HaveKey(asm.BuiltinFunc(ins.Constant)), "helper %v", asm.BuiltinFunc(ins.Constant))
				}
			}

			last := p.Instructions[len(p.Instructions)-1]
			Expect(last.OpCode.JumpOp()).To(Equal(asm.Exit))

			var buf bytes.Buffer
			Expect(p.Instructions.Marshal(&buf, binary.LittleEndian)).To(Succeed())
			Expect(buf.Len()).To(BeNumerically("<", 4096*8), "far below the kernel's instruction limit")
		},
		Entry("egress", bpf.EgressProgram, ebpf.AttachCGroupInetEgress),
		Entry("ingress", bpf.IngressProgram, ebpf.AttachCGroupInetIngress),
	)
})
