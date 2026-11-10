//go:build linux

// attached prints the eBPF programs attached to a cgroup for inet egress and
// ingress, one per line: "<egress|ingress> <program id> <program name>
// run_count=<n> run_time_ns=<n>". The run statistics are only collected while
// the kernel.bpf_stats_enabled sysctl is 1.
package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: attached <cgroup path>")
		os.Exit(2)
	}
	cgroup, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer cgroup.Close()

	for _, attach := range []struct {
		name string
		typ  ebpf.AttachType
	}{{"egress", ebpf.AttachCGroupInetEgress}, {"ingress", ebpf.AttachCGroupInetIngress}} {
		result, err := link.QueryPrograms(link.QueryOptions{Target: int(cgroup.Fd()), Attach: attach.typ})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, p := range result.Programs {
			name := "?"
			var runCount uint64
			var runTime int64
			if prog, err := ebpf.NewProgramFromID(p.ID); err == nil {
				if info, err := prog.Info(); err == nil {
					name = info.Name
					runCount, _ = info.RunCount()
					if d, ok := info.Runtime(); ok {
						runTime = d.Nanoseconds()
					}
				}
				prog.Close()
			}
			fmt.Printf("%s %d %s run_count=%d run_time_ns=%d\n", attach.name, p.ID, name, runCount, runTime)
		}
	}
}
