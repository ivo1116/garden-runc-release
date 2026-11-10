package capture

import (
	"encoding/binary"
	"fmt"
	"time"

	"code.cloudfoundry.org/guardian/dnsaudit/audit"
	"code.cloudfoundry.org/guardian/dnsaudit/bpf"
)

// Record layout, see package bpf.
const (
	recordHeaderLength = bpf.RecordHeaderLength
	MaxCaptureLength   = bpf.CaptureLength
	RecordLength       = bpf.RecordLength
)

type Record struct {
	CgroupID    uint64
	TimestampNs uint64
	PacketLen   uint32
	Direction   audit.Direction
	Data        []byte
}

func ParseRecord(raw []byte) (Record, error) {
	if len(raw) < recordHeaderLength {
		return Record{}, fmt.Errorf("record too short: %d bytes", len(raw))
	}
	captureLen := int(binary.LittleEndian.Uint16(raw[20:22]))
	if captureLen > MaxCaptureLength || recordHeaderLength+captureLen > len(raw) {
		return Record{}, fmt.Errorf("invalid capture length %d", captureLen)
	}
	data := make([]byte, captureLen)
	copy(data, raw[recordHeaderLength:recordHeaderLength+captureLen])
	return Record{
		CgroupID:    binary.LittleEndian.Uint64(raw[0:8]),
		TimestampNs: binary.LittleEndian.Uint64(raw[8:16]),
		PacketLen:   binary.LittleEndian.Uint32(raw[16:20]),
		Direction:   audit.Direction(raw[22]),
		Data:        data,
	}, nil
}

// Clock converts kernel monotonic timestamps (bpf_ktime_get_ns) to wall-clock
// time using an offset sampled at creation and on Resync.
type Clock struct {
	monotonic func() time.Duration
	now       func() time.Time
	offset    time.Duration
}

func NewClock(monotonic func() time.Duration, now func() time.Time) *Clock {
	c := &Clock{monotonic: monotonic, now: now}
	c.Resync()
	return c
}

func (c *Clock) Resync() {
	c.offset = time.Duration(c.now().UnixNano()) - c.monotonic()
}

func (c *Clock) Time(timestampNs uint64) time.Time {
	return time.Unix(0, int64(c.offset)+int64(timestampNs))
}

func (r Record) Event(clock *Clock) audit.Event {
	return audit.Event{
		CgroupID:  r.CgroupID,
		Time:      clock.Time(r.TimestampNs),
		Direction: r.Direction,
		Data:      r.Data,
	}
}
