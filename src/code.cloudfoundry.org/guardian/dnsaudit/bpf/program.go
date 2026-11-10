// Package bpf builds the eBPF programs of dns-audit with cilium/ebpf's asm
// package, so neither a C toolchain nor a compiled object is needed.
//
// Both programs copy DNS packets sent (egress) or received (ingress) by
// sockets in a cgroup subtree into a ring buffer, and always return 1: they
// never drop or change packets. They only use helpers that are not restricted
// to GPL-licensed programs.
package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Layout of a ring buffer record (little-endian):
//
//	0  u64 cgroup ID of the socket
//	8  u64 bpf_ktime_get_ns
//	16 u32 packet length
//	20 u16 captured length
//	22 u8  direction
//	23 u8  padding
//	24     first CaptureLength bytes of the packet, starting at the IP header
const (
	CaptureLength      = 640
	RecordHeaderLength = 24
	RecordLength       = RecordHeaderLength + CaptureLength

	DirectionEgress  = 0
	DirectionIngress = 1

	StatEvents      = 0
	StatRingbufFull = 1
	StatLoadErrors  = 2
	NumberOfStats   = 3

	EventsMap      = "events"
	StatsMap       = "stats"
	EgressProgram  = "dns_egress"
	IngressProgram = "dns_ingress"

	License = "Apache-2.0"

	dnsPort = 53

	// Waking up the reader for every event is expensive (an inter-processor
	// interrupt) and the cost lands in the sending process. The reader polls
	// instead and is only woken up when this much data is waiting.
	wakeupBytes = 64 * 1024

	// Flags of the ring buffer helpers (include/uapi/linux/bpf.h).
	ringbufAvailData   = 0
	ringbufNoWakeup    = 1
	ringbufForceWakeup = 2

	scratch  = -8  // stack slot for packet bytes
	statsKey = -16 // stack slot for the stats map key
)

// Spec returns the maps and both programs.
func Spec(ringBufferBytes uint32) *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			EventsMap: {Name: EventsMap, Type: ebpf.RingBuf, MaxEntries: ringBufferBytes},
			StatsMap: {
				Name:       StatsMap,
				Type:       ebpf.PerCPUArray,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: NumberOfStats,
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			EgressProgram:  Program(EgressProgram, ebpf.AttachCGroupInetEgress, DirectionEgress),
			IngressProgram: Program(IngressProgram, ebpf.AttachCGroupInetIngress, DirectionIngress),
		},
	}
}

// Program matches unfragmented (or first-fragment) IPv4 and IPv6 UDP or TCP
// packets to port 53 (egress) or from port 53 (ingress), skips TCP segments
// without payload, and copies the packet into the ring buffer. IPv6 extension
// headers are not followed.
//
// Registers R6-R9 survive helper calls: R6 holds the context, R7 the offset
// of the transport header, R8 the IP protocol and later the capture length,
// and R9 the reserved record.
func Program(name string, attachType ebpf.AttachType, direction int64) *ebpf.ProgramSpec {
	portOffset := int32(2) // destination port
	if direction == DirectionIngress {
		portOffset = 0 // source port
	}

	var insns asm.Instructions
	add := func(i ...asm.Instruction) { insns = append(insns, i...) }

	add(asm.Mov.Reg(asm.R6, asm.R1))

	// IP version from the first byte.
	add(loadBytes(asm.R10, 0, 1)...)
	add(
		asm.LoadMem(asm.R7, asm.RFP, scratch, asm.Byte),
		asm.Mov.Reg(asm.R8, asm.R7),
		asm.RSh.Imm(asm.R8, 4),
		asm.JEq.Imm(asm.R8, 4, "ipv4"),
		asm.JEq.Imm(asm.R8, 6, "ipv6"),
		asm.Ja.Label("exit"),
	)

	// IPv4: skip later fragments; the transport header starts at IHL * 4.
	add(label("ipv4", loadBytes(asm.R10, 6, 2))...)
	add(
		asm.LoadMem(asm.R2, asm.RFP, scratch, asm.Byte),
		asm.And.Imm(asm.R2, 0x1f),
		asm.LSh.Imm(asm.R2, 8),
		asm.LoadMem(asm.R3, asm.RFP, scratch+1, asm.Byte),
		asm.Or.Reg(asm.R2, asm.R3),
		asm.JNE.Imm(asm.R2, 0, "exit"),
		asm.And.Imm(asm.R7, 0x0f),
		asm.LSh.Imm(asm.R7, 2),
	)
	add(loadBytes(asm.R10, 9, 1)...)
	add(
		asm.LoadMem(asm.R8, asm.RFP, scratch, asm.Byte),
		asm.Ja.Label("transport"),
	)

	// IPv6: fixed 40-byte header; next header is the transport protocol.
	add(asm.Mov.Imm(asm.R7, 40).WithSymbol("ipv6"))
	add(loadBytes(asm.R10, 6, 1)...)
	add(asm.LoadMem(asm.R8, asm.RFP, scratch, asm.Byte))

	// UDP or TCP only.
	add(
		asm.JEq.Imm(asm.R8, 17, "port").WithSymbol("transport"),
		asm.JEq.Imm(asm.R8, 6, "port"),
		asm.Ja.Label("exit"),
	)

	// Port 53.
	add(label("port", loadBytes(asm.R7, portOffset, 2))...)
	add(
		asm.LoadMem(asm.R2, asm.RFP, scratch, asm.Byte),
		asm.LSh.Imm(asm.R2, 8),
		asm.LoadMem(asm.R3, asm.RFP, scratch+1, asm.Byte),
		asm.Or.Reg(asm.R2, asm.R3),
		asm.JNE.Imm(asm.R2, dnsPort, "exit"),
		asm.JNE.Imm(asm.R8, 6, "capture"),
	)

	// TCP: skip segments without payload (packet length <= end of TCP header).
	add(loadBytes(asm.R7, 12, 1)...)
	add(
		asm.LoadMem(asm.R2, asm.RFP, scratch, asm.Byte),
		asm.RSh.Imm(asm.R2, 4),
		asm.LSh.Imm(asm.R2, 2),
		asm.Add.Reg(asm.R2, asm.R7),
		asm.LoadMem(asm.R3, asm.R6, 0, asm.Word), // skb->len
		asm.JLE.Reg(asm.R3, asm.R2, "exit"),
	)

	// Reserve a record; count and give up if the ring buffer is full.
	add(
		asm.LoadMapPtr(asm.R1, 0).WithReference(EventsMap).WithSymbol("capture"),
		asm.Mov.Imm(asm.R2, RecordLength),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "ringbuf_full"),
		asm.Mov.Reg(asm.R9, asm.R0),

		// Packet length, and the capture length min(len, CaptureLength).
		asm.LoadMem(asm.R8, asm.R6, 0, asm.Word),
		asm.StoreMem(asm.R9, 16, asm.R8, asm.Word),
		asm.JLE.Imm(asm.R8, CaptureLength, "length_ok"),
		asm.Mov.Imm(asm.R8, CaptureLength),
		asm.JEq.Imm(asm.R8, 0, "discard").WithSymbol("length_ok"),

		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnSkbCgroupId.Call(),
		asm.StoreMem(asm.R9, 0, asm.R0, asm.DWord),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R9, 8, asm.R0, asm.DWord),
		asm.StoreImm(asm.R9, 22, direction, asm.Byte),
		asm.StoreImm(asm.R9, 23, 0, asm.Byte),

		// Copy the packet into the record.
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.R9),
		asm.Add.Imm(asm.R3, RecordHeaderLength),
		asm.Mov.Reg(asm.R4, asm.R8),
		asm.FnSkbLoadBytes.Call(),
		asm.JSLT.Imm(asm.R0, 0, "discard"),
		asm.StoreMem(asm.R9, 20, asm.R8, asm.Half),

		// Submit, waking up the reader only when a backlog builds up.
		asm.LoadMapPtr(asm.R1, 0).WithReference(EventsMap),
		asm.Mov.Imm(asm.R2, ringbufAvailData),
		asm.FnRingbufQuery.Call(),
		asm.Mov.Imm(asm.R2, ringbufNoWakeup),
		asm.JLT.Imm(asm.R0, wakeupBytes, "submit"),
		asm.Mov.Imm(asm.R2, ringbufForceWakeup),
		asm.Mov.Reg(asm.R1, asm.R9).WithSymbol("submit"),
		asm.FnRingbufSubmit.Call(),
	)
	add(count(StatEvents)...)
	add(asm.Ja.Label("exit"))

	add(
		asm.Mov.Reg(asm.R1, asm.R9).WithSymbol("discard"),
		asm.Mov.Imm(asm.R2, ringbufNoWakeup),
		asm.FnRingbufDiscard.Call(),
	)
	add(count(StatLoadErrors)...)
	add(asm.Ja.Label("exit"))

	add(label("ringbuf_full", count(StatRingbufFull))...)

	add(
		asm.Mov.Imm(asm.R0, 1).WithSymbol("exit"),
		asm.Return(),
	)

	return &ebpf.ProgramSpec{
		Name:         name,
		Type:         ebpf.CGroupSKB,
		AttachType:   attachType,
		Instructions: insns,
		License:      License,
	}
}

// loadBytes copies length bytes at base+offset of the packet to the scratch
// stack slot; base R10 means offset is absolute. It exits when the packet is
// too short.
func loadBytes(base asm.Register, offset int32, length int32) asm.Instructions {
	var setOffset asm.Instructions
	if base == asm.R10 {
		setOffset = asm.Instructions{asm.Mov.Imm(asm.R2, offset)}
	} else {
		setOffset = asm.Instructions{asm.Mov.Reg(asm.R2, base), asm.Add.Imm(asm.R2, offset)}
	}
	insns := asm.Instructions{asm.Mov.Reg(asm.R1, asm.R6)}
	insns = append(insns, setOffset...)
	return append(insns,
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, scratch),
		asm.Mov.Imm(asm.R4, length),
		asm.FnSkbLoadBytes.Call(),
		asm.JSLT.Imm(asm.R0, 0, "exit"),
	)
}

// count increments a per-CPU counter.
func count(key int64) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.RFP, statsKey, key, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference(StatsMap),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, statsKey),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
	}
}

func label(name string, insns asm.Instructions) asm.Instructions {
	insns[0] = insns[0].WithSymbol(name)
	return insns
}
