//go:build linux

package capture

import (
	"errors"
	"fmt"
	"os"
	"time"

	"code.cloudfoundry.org/guardian/dnsaudit/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type Stats struct {
	Events      uint64
	RingbufFull uint64
	LoadErrors  uint64
}

// Capture holds the loaded eBPF programs, their cgroup links and the ring
// buffer reader. Closing it (or exiting the process) detaches the programs.
type Capture struct {
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
}

// Open loads the programs and attaches the egress program, and the ingress
// program when responses is set, to the cgroup at cgroupRoot. The programs
// apply to every descendant cgroup and coexist with other programs.
func Open(cgroupRoot string, ringBufferBytes int, responses bool) (*Capture, error) {
	collection, err := ebpf.NewCollection(bpf.Spec(uint32(ringBufferBytes)))
	if err != nil {
		var verifierError *ebpf.VerifierError
		if errors.As(err, &verifierError) {
			return nil, fmt.Errorf("load programs: %+v", verifierError)
		}
		return nil, fmt.Errorf("load programs: %w", err)
	}
	c := &Capture{collection: collection}

	if err := c.attach(cgroupRoot, ebpf.AttachCGroupInetEgress, collection.Programs[bpf.EgressProgram]); err != nil {
		c.Close()
		return nil, err
	}
	if responses {
		if err := c.attach(cgroupRoot, ebpf.AttachCGroupInetIngress, collection.Programs[bpf.IngressProgram]); err != nil {
			c.Close()
			return nil, err
		}
	}

	c.reader, err = ringbuf.NewReader(collection.Maps[bpf.EventsMap])
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	return c, nil
}

func (c *Capture) attach(cgroupRoot string, attachType ebpf.AttachType, program *ebpf.Program) error {
	l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupRoot, Attach: attachType, Program: program})
	if err != nil {
		return fmt.Errorf("attach %s to %s: %w", attachType, cgroupRoot, err)
	}
	c.links = append(c.links, l)
	return nil
}

// The programs don't wake up the reader for every event, so the reader also
// polls at this interval.
const pollInterval = 50 * time.Millisecond

// Read waits up to the poll interval for a record. It returns false when no
// record is available, and os.ErrClosed after Close.
func (c *Capture) Read() (Record, bool, error) {
	c.reader.SetDeadline(time.Now().Add(pollInterval))
	raw, err := c.reader.Read()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return Record{}, false, nil
		}
		if errors.Is(err, ringbuf.ErrClosed) {
			return Record{}, false, os.ErrClosed
		}
		return Record{}, false, err
	}
	record, err := ParseRecord(raw.RawSample)
	return record, err == nil, err
}

func (c *Capture) Stats() (Stats, error) {
	var values [bpf.NumberOfStats]uint64
	for key := uint32(0); key < bpf.NumberOfStats; key++ {
		var perCPU []uint64
		if err := c.collection.Maps[bpf.StatsMap].Lookup(key, &perCPU); err != nil {
			return Stats{}, fmt.Errorf("read stats: %w", err)
		}
		for _, v := range perCPU {
			values[key] += v
		}
	}
	return Stats{Events: values[bpf.StatEvents], RingbufFull: values[bpf.StatRingbufFull], LoadErrors: values[bpf.StatLoadErrors]}, nil
}

// Detach detaches the programs from the cgroup. Records already in the ring
// buffer can still be read.
func (c *Capture) Detach() error {
	var errs []error
	for _, l := range c.links {
		errs = append(errs, l.Close())
	}
	c.links = nil
	return errors.Join(errs...)
}

// Close detaches the programs and frees the ring buffer. It interrupts Read
// and may be called more than once.
func (c *Capture) Close() error {
	errs := []error{c.Detach()}
	if c.reader != nil {
		errs = append(errs, c.reader.Close())
	}
	if c.collection != nil {
		c.collection.Close()
	}
	return errors.Join(errs...)
}

func Monotonic() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}
